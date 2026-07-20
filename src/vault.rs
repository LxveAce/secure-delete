//! The crypto-erase vault — the SSD solve.
//!
//! Files are encrypted on INGEST (plaintext never lands on flash as a normal file). Each file gets its
//! own random data key (DEK); DEKs live only inside a per-file `meta` blob that is itself encrypted under
//! a random per-vault master key (MK); MK is wrapped under a *wrap key* and is never persisted in the clear.
//!
//! The wrap key depends on the vault's ROOT:
//! - **Software root** (default, back-compatible): `wrap_key = KEK = Argon2id(passphrase, salt)`.
//! - **TPM/hardware root** (opt-in, `init --tpm`): `wrap_key = HKDF(RWK ‖ KEK)`, where RWK is a random key
//!   sealed by the TPM. Both the hardware *and* the passphrase are mandatory to open. Destroying the TPM
//!   key (`hardware-shred`) makes any stale wrapped-master in flash un-openable even with the passphrase —
//!   the strongest erase this tool offers. Honest boundary: on Windows the TPM key is an SRK-wrapped blob
//!   on disk usable only on *this* TPM, so this is defense-in-depth, not an absolute in-hardware erase.
//!
//! To SHRED a file we drop its entry, best-effort-overwrite its ciphertext blob, and RE-KEY the vault
//! (fresh MK, survivors re-sealed, old wrapped-master overwritten). A whole-vault `rekey` (passphrase
//! change) rotates the software factor; `hardware-shred` additionally rotates the TPM factor.
use crate::crypto::{aead_decrypt, aead_encrypt, derive_kek, random_bytes, KEY_LEN, NONCE_LEN};
use crate::keyroot::{self, derive_wrap_key, KeyRoot, RootCtx, RWK_LEN};
use crate::overwrite::best_effort_overwrite_delete;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// Argon2id cost defaults (RFC 9106-informed): 64 MiB, 3 passes, 1 lane.
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

const VERSION_SOFTWARE: u32 = 1; // legacy passphrase-only header (byte-identical to pre-TPM releases)
const VERSION_TPM: u32 = 2; // written only when a hardware root and/or recovery block is present
const VERSION_MAX_KNOWN: u32 = 2; // refuse to open a header newer than we understand

#[derive(Serialize, Deserialize, Clone)]
struct Kdf {
    alg: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Kdf {
    fn argon2id(salt_b64: String) -> Self {
        Kdf { alg: "argon2id".into(), salt: salt_b64, m_cost: M_COST, t_cost: T_COST, p_cost: P_COST }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Sealed {
    nonce: String,
    ct: String, // AEAD output (ciphertext||tag), base64
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    id: String,
    meta: Sealed, // {name, dek} sealed under the master key
    blob_nonce: String,
    size: u64,
}

/// How the master key is protected. A missing `root` (old vault) deserializes to `Passphrase`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind")]
enum Root {
    #[serde(rename = "passphrase")]
    Passphrase,
    #[serde(rename = "tpm+passphrase")]
    TpmPassphrase {
        provider: String,
        scope: String,
        key_id: String,
        wrapped_rwk: String,
    },
}

fn default_root() -> Root {
    Root::Passphrase
}
fn is_passphrase(r: &Root) -> bool {
    matches!(r, Root::Passphrase)
}

/// Optional off-device recovery escrow: the RWK sealed under a passphrase-strength *recovery code* the
/// user stores off the machine. Lets a TPM vault be reopened if the TPM is lost. Still needs the vault
/// passphrase (the code only substitutes for the hardware), so it is not a single-factor bypass.
#[derive(Serialize, Deserialize, Clone)]
struct Recovery {
    kdf: Kdf,
    sealed_rwk: Sealed, // Seal(recoveryKEK, RWK), AAD = "recovery"
}

#[derive(Serialize, Deserialize)]
struct Header {
    version: u32,
    kdf: Kdf,
    #[serde(default = "default_root", skip_serializing_if = "is_passphrase")]
    root: Root,
    wrapped_master: Sealed,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<Recovery>,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    name: String,
    dek: String, // base64 DEK
}

/// Canonical descriptor bound into the master seal's AAD and the HKDF `info`, so a tampered header
/// (root downgrade, cost reduction, wrapped-RWK swap) fails the AEAD tag instead of deriving a live key.
#[derive(Serialize)]
struct WrapAad<'a> {
    version: u32,
    kind: &'a str,
    provider: &'a str,
    key_id: &'a str,
    wrapped_rwk: &'a str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &'a str,
}

/// What `init --tpm` / `hardware-shred` hand back to the CLI to print.
pub struct TpmReport {
    pub provider: String,
    pub key_id: String,
    pub recovery_code: Option<String>,
}

/// The honest per-vault root state for `status`.
pub enum RootReport {
    Software,
    Tpm {
        provider: String,
        key_id: String,
        scope: String,
        present: std::result::Result<bool, String>,
        has_recovery: bool,
        interrupted_shred: bool,
    },
}

/// A borrowed-or-owned handle to the key root, so tests can inject a `MockKeyRoot` while production
/// builds a fresh platform root per call.
enum Hw<'a> {
    Ref(&'a dyn KeyRoot),
    Owned(Box<dyn KeyRoot>),
}
impl Hw<'_> {
    fn get(&self) -> &dyn KeyRoot {
        match self {
            Hw::Ref(r) => *r,
            Hw::Owned(b) => b.as_ref(),
        }
    }
}

/// Persisted marker that a `hardware-shred` was interrupted after the new key was live but before the old
/// key was destroyed — so the old TPM key may still exist. `repair_destroy` retries it.
#[derive(Serialize, Deserialize)]
struct Pending {
    provider: String,
    scope: String,
    key_id: String,
}

pub struct Vault {
    root: PathBuf,
    injected: Option<Box<dyn KeyRoot>>,
}

impl Vault {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Vault { root: root.into(), injected: None }
    }

    /// Construct a vault with an explicit key root (used by tests to inject `MockKeyRoot`).
    pub fn with_key_root(root: impl Into<PathBuf>, kr: Box<dyn KeyRoot>) -> Self {
        Vault { root: root.into(), injected: Some(kr) }
    }

    fn header_path(&self) -> PathBuf {
        self.root.join("header.json")
    }
    fn pending_path(&self) -> PathBuf {
        self.root.join("header.pending")
    }
    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }
    fn blob_path(&self, id: &str) -> PathBuf {
        self.blobs_dir().join(format!("{id}.bin"))
    }

    /// The key root for `provider`: the injected one if present, else a fresh platform root.
    fn hw(&self, provider: &str) -> Hw<'_> {
        match &self.injected {
            Some(b) => Hw::Ref(b.as_ref()),
            None => Hw::Owned(keyroot::root_for_provider(provider)),
        }
    }

    fn load(&self) -> Result<Header> {
        let s = fs::read_to_string(self.header_path())
            .context("could not open the vault header (is this a vault directory?)")?;
        let h: Header = serde_json::from_str(&s)?;
        if h.version > VERSION_MAX_KNOWN {
            bail!(
                "this vault (version {}) was written by a newer secure-delete — upgrade the tool to open it",
                h.version
            );
        }
        Ok(h)
    }

    fn store(&self, h: &Header) -> Result<()> {
        let hp = self.header_path();
        let tmp = self.root.join("header.json.tmp");
        let bytes = serde_json::to_vec_pretty(h)?;
        {
            // fsync the new header before we drop the old one, so a crash can't leave a torn/empty header.
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        if hp.exists() {
            best_effort_overwrite_delete(&hp)?;
        }
        fs::rename(&tmp, &hp)?;
        Ok(())
    }

    fn seal_with(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        let ct = aead_encrypt(key, &nonce, plaintext, aad)?;
        Ok(Sealed { nonce: B64.encode(nonce), ct: B64.encode(ct) })
    }

    fn unseal_with(key: &[u8; KEY_LEN], s: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = B64
            .decode(&s.nonce)?
            .try_into()
            .map_err(|_| anyhow!("bad nonce length"))?;
        let ct = B64.decode(&s.ct)?;
        aead_decrypt(key, &nonce, &ct, aad)
    }

    // meta/blob layers keep empty AAD (unchanged, back-compatible).
    fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Sealed> {
        Self::seal_with(key, plaintext, b"")
    }
    fn unseal(key: &[u8; KEY_LEN], s: &Sealed) -> Result<Vec<u8>> {
        Self::unseal_with(key, s, b"")
    }

    /// The AAD that binds the master seal. Empty for legacy software vaults (byte-identical), the
    /// canonical [`WrapAad`] for hardware vaults.
    fn master_aad(h: &Header) -> Vec<u8> {
        match &h.root {
            Root::Passphrase => Vec::new(),
            Root::TpmPassphrase { provider, key_id, wrapped_rwk, .. } => serde_json::to_vec(&WrapAad {
                version: h.version,
                kind: "tpm+passphrase",
                provider,
                key_id,
                wrapped_rwk,
                m_cost: h.kdf.m_cost,
                t_cost: h.kdf.t_cost,
                p_cost: h.kdf.p_cost,
                salt: &h.kdf.salt,
            })
            .unwrap_or_default(),
        }
    }

    /// Derive the master-wrapping key for `h`. For a hardware root the TPM is unsealed FIRST, so a
    /// missing/failed TPM surfaces as a hardware error — never silently as "wrong passphrase", and never
    /// via a software fallback.
    fn wrap_key(&self, h: &Header, passphrase: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let salt = B64.decode(&h.kdf.salt)?;
        match &h.root {
            Root::Passphrase => derive_kek(passphrase, &salt, h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost),
            Root::TpmPassphrase { provider, scope, key_id, wrapped_rwk } => {
                let hw = self.hw(provider);
                let ctx = RootCtx { key_id: key_id.clone(), scope: scope.clone() };
                let rwk = hw
                    .get()
                    .unseal_rwk(&ctx, wrapped_rwk)
                    .map_err(|e| anyhow!("hardware key root ({provider}): {e}"))?;
                let kek = derive_kek(passphrase, &salt, h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost)?;
                derive_wrap_key(&rwk, &kek, &salt, h.version, provider, key_id, wrapped_rwk)
            }
        }
    }

    fn open_master(&self, h: &Header, passphrase: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let wk = self.wrap_key(h, passphrase)?;
        let aad = Self::master_aad(h);
        let mk_vec = Self::unseal_with(&wk, &h.wrapped_master, &aad)?;
        let mk: [u8; KEY_LEN] = mk_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("corrupt master key"))?;
        Ok(Zeroizing::new(mk))
    }

    /// Create a new empty **software** vault protected by `passphrase` (unchanged, back-compatible).
    pub fn init(&self, passphrase: &[u8]) -> Result<()> {
        if self.header_path().exists() {
            bail!("a vault already exists at {}", self.root.display());
        }
        fs::create_dir_all(self.blobs_dir())?;
        let salt = random_bytes::<16>()?;
        let kek = derive_kek(passphrase, &salt, M_COST, T_COST, P_COST)?;
        let mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let wrapped_master = Self::seal_with(&kek, mk.as_ref(), b"")?;
        let h = Header {
            version: VERSION_SOFTWARE,
            kdf: Kdf::argon2id(B64.encode(salt)),
            root: Root::Passphrase,
            wrapped_master,
            recovery: None,
            entries: vec![],
        };
        self.store(&h)
    }

    /// Create a new empty **hardware-rooted** vault: a random RWK is sealed by the TPM, and the master is
    /// wrapped under `HKDF(RWK ‖ KEK)`. Unless `skip_recovery`, a recovery code is minted and returned
    /// (printed once, never stored) so the vault survives TPM loss.
    pub fn init_tpm(&self, passphrase: &[u8], skip_recovery: bool) -> Result<TpmReport> {
        if self.header_path().exists() {
            bail!("a vault already exists at {}", self.root.display());
        }
        let hw = self.hw(keyroot::default_provider());
        let provider = hw.get().provider_id().to_string();
        let key_id = mint_key_id()?;
        let ctx = RootCtx::new(&key_id);

        let rwk = Zeroizing::new(random_bytes::<RWK_LEN>()?);
        let wrapped_rwk = hw
            .get()
            .seal_rwk(&ctx, &rwk)
            .map_err(|e| anyhow!("could not enroll a hardware key ({provider}): {e}"))?;

        let salt = random_bytes::<16>()?;
        let salt_b64 = B64.encode(salt);
        let kek = derive_kek(passphrase, &salt, M_COST, T_COST, P_COST)?;
        let wk = derive_wrap_key(&rwk, &kek, &salt, VERSION_TPM, &provider, &key_id, &wrapped_rwk)?;
        let mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);

        // recovery escrow (seals the RWK, so routine shred/rekey never invalidate it)
        let (recovery, recovery_code) = if skip_recovery {
            (None, None)
        } else {
            let (code, block) = mint_recovery(&rwk)?;
            (Some(block), Some(code))
        };

        let mut h = Header {
            version: VERSION_TPM,
            kdf: Kdf::argon2id(salt_b64),
            root: Root::TpmPassphrase { provider: provider.clone(), scope: ctx.scope.clone(), key_id: key_id.clone(), wrapped_rwk },
            wrapped_master: Sealed { nonce: String::new(), ct: String::new() }, // filled below
            recovery,
            entries: vec![],
        };
        let aad = Self::master_aad(&h);
        h.wrapped_master = Self::seal_with(&wk, mk.as_ref(), &aad)?;

        fs::create_dir_all(self.blobs_dir())?;
        self.store(&h)?;
        Ok(TpmReport { provider, key_id, recovery_code })
    }

    /// Encrypt `file` into the vault. Returns its entry id.
    pub fn add(&self, passphrase: &[u8], file: &Path) -> Result<String> {
        let mut h = self.load()?;
        let mk = self.open_master(&h, passphrase)?;
        let data = Zeroizing::new(fs::read(file).with_context(|| format!("read {}", file.display()))?);
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let dek = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let blob_nonce = random_bytes::<NONCE_LEN>()?;
        let blob = aead_encrypt(&dek, &blob_nonce, &data, b"")?;
        let id = new_id()?;
        fs::create_dir_all(self.blobs_dir())?;
        fs::write(self.blob_path(&id), &blob)?;
        let meta = Meta { name, dek: B64.encode(dek.as_ref()) };
        let meta_sealed = Self::seal(&mk, &serde_json::to_vec(&meta)?)?;
        h.entries.push(Entry {
            id: id.clone(),
            meta: meta_sealed,
            blob_nonce: B64.encode(blob_nonce),
            size: data.len() as u64,
        });
        self.store(&h)?;
        Ok(id)
    }

    /// List entries as (id, name, size).
    pub fn list(&self, passphrase: &[u8]) -> Result<Vec<(String, String, u64)>> {
        let h = self.load()?;
        let mk = self.open_master(&h, passphrase)?;
        let mut out = vec![];
        for e in &h.entries {
            let meta: Meta = serde_json::from_slice(&Self::unseal(&mk, &e.meta)?)?;
            out.push((e.id.clone(), meta.name, e.size));
        }
        Ok(out)
    }

    /// Decrypt an entry out of the vault into `out_dir`. Returns the written path.
    pub fn open(&self, passphrase: &[u8], id: &str, out_dir: &Path) -> Result<PathBuf> {
        let h = self.load()?;
        let mk = self.open_master(&h, passphrase)?;
        let e = h
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow!("no such entry: {id}"))?;
        let meta: Meta = serde_json::from_slice(&Self::unseal(&mk, &e.meta)?)?;
        let dek: [u8; KEY_LEN] = B64
            .decode(&meta.dek)?
            .try_into()
            .map_err(|_| anyhow!("corrupt data key"))?;
        let blob = fs::read(self.blob_path(id))?;
        let blob_nonce: [u8; NONCE_LEN] = B64
            .decode(&e.blob_nonce)?
            .try_into()
            .map_err(|_| anyhow!("bad blob nonce"))?;
        let data = Zeroizing::new(aead_decrypt(&dek, &blob_nonce, &blob, b"")?);
        fs::create_dir_all(out_dir)?;
        let out = out_dir.join(&meta.name);
        fs::write(&out, &data)?;
        Ok(out)
    }

    /// Rotate the master key: fresh MK, every survivor meta re-sealed, wrapped-master re-wrapped under the
    /// CURRENT wrap key, old header overwritten. Shared by `shred` and (with an id) file removal. The
    /// hardware factor (RWK) is deliberately left untouched — see `hardware_shred`.
    fn rotate_master(&self, h: &mut Header, passphrase: &[u8], drop_id: Option<&str>) -> Result<()> {
        let old_mk = self.open_master(h, passphrase)?;
        let mut survivors: Vec<(Entry, Zeroizing<Vec<u8>>)> = vec![];
        for e in &h.entries {
            if Some(e.id.as_str()) == drop_id {
                continue;
            }
            let meta_pt = Zeroizing::new(Self::unseal(&old_mk, &e.meta)?);
            survivors.push((e.clone(), meta_pt));
        }
        if let Some(id) = drop_id {
            let _ = best_effort_overwrite_delete(&self.blob_path(id));
        }
        let wk = self.wrap_key(h, passphrase)?; // current root (RWK unchanged here)
        let new_mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let mut new_entries = vec![];
        for (mut e, meta_pt) in survivors {
            e.meta = Self::seal(&new_mk, &meta_pt)?;
            new_entries.push(e);
        }
        let aad = Self::master_aad(h);
        h.wrapped_master = Self::seal_with(&wk, new_mk.as_ref(), &aad)?;
        h.entries = new_entries;
        Ok(())
    }

    /// Crypto-erase an entry: drop its key, overwrite its blob, and rotate the master so stale copies of
    /// the dropped meta become useless. (Software crypto-erase; does not touch the TPM factor.)
    pub fn shred(&self, passphrase: &[u8], id: &str) -> Result<()> {
        let mut h = self.load()?;
        if !h.entries.iter().any(|e| e.id == id) {
            bail!("no such entry: {id}");
        }
        self.rotate_master(&mut h, passphrase, Some(id))?;
        self.store(&h)
    }

    /// Re-key the WHOLE vault under a NEW passphrase — a whole-vault crypto-erase of the software factor.
    /// Fresh salt + KEK; the master and every entry are rotated. For a hardware vault the RWK is unchanged
    /// (so the recovery kit stays valid), but the wrap key changes because the KEK does.
    pub fn rekey(&self, old_passphrase: &[u8], new_passphrase: &[u8]) -> Result<()> {
        let mut h = self.load()?;
        let old_mk = self.open_master(&h, old_passphrase)?;
        let mut items: Vec<(Entry, Zeroizing<Vec<u8>>)> = vec![];
        for e in &h.entries {
            items.push((e.clone(), Zeroizing::new(Self::unseal(&old_mk, &e.meta)?)));
        }
        // Recover the RWK (if any) under the OLD header, BEFORE we change the salt, so we can re-wrap.
        let rwk = self.recover_rwk(&h, old_passphrase)?;

        let salt = random_bytes::<16>()?;
        h.kdf = Kdf::argon2id(B64.encode(salt));
        let kek = derive_kek(new_passphrase, &salt, M_COST, T_COST, P_COST)?;
        let wk = self.wrap_key_from_parts(&h, &kek, &salt, rwk.as_deref())?;

        let new_mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let mut new_entries = vec![];
        for (mut e, pt) in items {
            e.meta = Self::seal(&new_mk, &pt)?;
            new_entries.push(e);
        }
        let aad = Self::master_aad(&h);
        h.wrapped_master = Self::seal_with(&wk, new_mk.as_ref(), &aad)?;
        h.entries = new_entries;
        self.store(&h)
    }

    /// Rotate the HARDWARE factor: create a fresh TPM key (new RWK), re-wrap everything under it, verify
    /// it opens, then destroy the old TPM key — so any stale wrapped-master in flash becomes un-openable
    /// even with the passphrase. Optionally also shreds `drop_id`. Crash-safe (persist-then-destroy).
    pub fn hardware_shred(&self, passphrase: &[u8], drop_id: Option<&str>, destroy_recovery_kit: bool) -> Result<TpmReport> {
        let mut h = self.load()?;
        let (provider, old_scope, old_key_id) = match &h.root {
            Root::TpmPassphrase { provider, scope, key_id, .. } => (provider.clone(), scope.clone(), key_id.clone()),
            Root::Passphrase => bail!("this is a software vault — use `rekey` (or `init --tpm` for a new hardware vault)"),
        };
        if let Some(id) = drop_id {
            if !h.entries.iter().any(|e| e.id == id) {
                bail!("no such entry: {id}");
            }
        }

        // Decrypt survivors under the OLD master before anything changes.
        let old_mk = self.open_master(&h, passphrase)?;
        let mut survivors: Vec<(Entry, Zeroizing<Vec<u8>>)> = vec![];
        for e in &h.entries {
            if Some(e.id.as_str()) == drop_id {
                continue;
            }
            survivors.push((e.clone(), Zeroizing::new(Self::unseal(&old_mk, &e.meta)?)));
        }

        // 1) NEW TPM key + NEW RWK.
        let hw = self.hw(&provider);
        let new_key_id = mint_key_id()?;
        let new_ctx = RootCtx::new(&new_key_id);
        let new_rwk = Zeroizing::new(random_bytes::<RWK_LEN>()?);
        let new_wrapped_rwk = hw
            .get()
            .seal_rwk(&new_ctx, &new_rwk)
            .map_err(|e| anyhow!("could not create the new hardware key ({provider}): {e}"))?;

        // 2) rebuild the header under the new root.
        let salt = B64.decode(&h.kdf.salt)?;
        let kek = derive_kek(passphrase, &salt, h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost)?;
        h.root = Root::TpmPassphrase { provider: provider.clone(), scope: new_ctx.scope.clone(), key_id: new_key_id.clone(), wrapped_rwk: new_wrapped_rwk.clone() };
        let wk = derive_wrap_key(&new_rwk, &kek, &salt, h.version, &provider, &new_key_id, &new_wrapped_rwk)?;
        let new_mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let mut new_entries = vec![];
        for (mut e, pt) in survivors {
            e.meta = Self::seal(&new_mk, &pt)?;
            new_entries.push(e);
        }
        h.entries = new_entries;

        // re-mint or drop the recovery kit (it sealed the OLD RWK, now dead).
        let recovery_code = if destroy_recovery_kit {
            h.recovery = None;
            None
        } else if h.recovery.is_some() {
            let (code, block) = mint_recovery(&new_rwk)?;
            h.recovery = Some(block);
            Some(code)
        } else {
            None
        };

        let aad = Self::master_aad(&h);
        h.wrapped_master = Self::seal_with(&wk, new_mk.as_ref(), &aad)?;

        if let Some(id) = drop_id {
            let _ = best_effort_overwrite_delete(&self.blob_path(id));
        }

        // 3) persist the new header (fsync inside store).
        self.store(&h)?;

        // 4) verify-reopen gate: prove the new key really opens the vault before destroying the old one.
        self.open_master(&h, passphrase)
            .context("new hardware key failed verification — old key left intact; nothing was destroyed")?;

        // 5) record the pending destroy, then 6) destroy the old key and clear the marker.
        let pending = Pending { provider: provider.clone(), scope: old_scope.clone(), key_id: old_key_id.clone() };
        fs::write(self.pending_path(), serde_json::to_vec(&pending)?)?;
        let old_ctx = RootCtx { key_id: old_key_id.clone(), scope: old_scope };
        hw.get()
            .destroy(&old_ctx)
            .map_err(|e| anyhow!("new key is live, but the OLD key {old_key_id} could not be destroyed ({e}); run `repair-destroy`"))?;
        let _ = fs::remove_file(self.pending_path());

        Ok(TpmReport { provider, key_id: new_key_id, recovery_code })
    }

    /// Retry a `hardware-shred` whose old-key destroy was interrupted (a `header.pending` remains).
    pub fn repair_destroy(&self) -> Result<bool> {
        let pp = self.pending_path();
        if !pp.exists() {
            return Ok(false);
        }
        let p: Pending = serde_json::from_slice(&fs::read(&pp)?)?;
        let hw = self.hw(&p.provider);
        let ctx = RootCtx { key_id: p.key_id.clone(), scope: p.scope };
        hw.get()
            .destroy(&ctx)
            .map_err(|e| anyhow!("could not destroy the leftover key {}: {e}", p.key_id))?;
        fs::remove_file(&pp)?;
        Ok(true)
    }

    /// Reopen a TPM vault whose hardware is unavailable, using the off-device recovery code + passphrase.
    /// Default: re-provision a fresh TPM key on THIS machine. `to_software`: convert to a software vault.
    pub fn recover(&self, recovery_code: &str, passphrase: &[u8], to_software: bool) -> Result<TpmReport> {
        let mut h = self.load()?;
        let rec = h.recovery.clone().ok_or_else(|| anyhow!("this vault has no recovery kit"))?;
        let (provider0, _scope0) = match &h.root {
            Root::TpmPassphrase { provider, scope, .. } => (provider.clone(), scope.clone()),
            Root::Passphrase => bail!("this is already a software vault"),
        };
        // RWK from the recovery code.
        let code = normalize_code(recovery_code)?;
        let rsalt = B64.decode(&rec.kdf.salt)?;
        let rkek = derive_kek(&code, &rsalt, rec.kdf.m_cost, rec.kdf.t_cost, rec.kdf.p_cost)?;
        let rwk_vec = Self::unseal_with(&rkek, &rec.sealed_rwk, b"recovery")
            .context("recovery failed — wrong recovery code")?;
        let rwk: Zeroizing<[u8; RWK_LEN]> = Zeroizing::new(
            rwk_vec.as_slice().try_into().map_err(|_| anyhow!("corrupt recovery block"))?,
        );

        // MK under the OLD header (using the recovered RWK + passphrase).
        let salt = B64.decode(&h.kdf.salt)?;
        let kek = derive_kek(passphrase, &salt, h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost)?;
        let old_wk = self.wrap_key_from_parts(&h, &kek, &salt, Some(&rwk))?;
        let old_aad = Self::master_aad(&h);
        let mk_vec = Self::unseal_with(&old_wk, &h.wrapped_master, &old_aad)
            .context("recovery failed — wrong passphrase")?;
        let mk: [u8; KEY_LEN] = mk_vec.as_slice().try_into().map_err(|_| anyhow!("corrupt master"))?;
        let mk = Zeroizing::new(mk);

        if to_software {
            // Convert to a software vault: wrap MK under the KEK, drop the hardware root + recovery.
            h.version = VERSION_SOFTWARE;
            h.root = Root::Passphrase;
            h.recovery = None;
            let aad = Self::master_aad(&h); // empty now
            h.wrapped_master = Self::seal_with(&kek, mk.as_ref(), &aad)?;
            self.store(&h)?;
            return Ok(TpmReport { provider: "software".into(), key_id: String::new(), recovery_code: None });
        }

        // Re-provision a fresh TPM key on this machine, re-wrap master + recovery under the new RWK.
        let hw = self.hw(&provider0);
        let provider = hw.get().provider_id().to_string();
        let key_id = mint_key_id()?;
        let ctx = RootCtx::new(&key_id);
        let new_rwk = Zeroizing::new(random_bytes::<RWK_LEN>()?);
        let wrapped_rwk = hw
            .get()
            .seal_rwk(&ctx, &new_rwk)
            .map_err(|e| anyhow!("could not enroll a hardware key ({provider}): {e}"))?;
        h.version = VERSION_TPM;
        h.root = Root::TpmPassphrase { provider: provider.clone(), scope: ctx.scope.clone(), key_id: key_id.clone(), wrapped_rwk: wrapped_rwk.clone() };
        let wk = derive_wrap_key(&new_rwk, &kek, &salt, h.version, &provider, &key_id, &wrapped_rwk)?;
        let aad = Self::master_aad(&h);
        h.wrapped_master = Self::seal_with(&wk, mk.as_ref(), &aad)?;
        let (code, block) = mint_recovery(&new_rwk)?;
        h.recovery = Some(block);
        self.store(&h)?;
        Ok(TpmReport { provider, key_id, recovery_code: Some(code) })
    }

    /// Honest root state for `status` — reads the header and (for TPM vaults) probes the key.
    pub fn root_report(&self) -> Result<RootReport> {
        let h = self.load()?;
        match &h.root {
            Root::Passphrase => Ok(RootReport::Software),
            Root::TpmPassphrase { provider, scope, key_id, .. } => {
                let hw = self.hw(provider);
                let ctx = RootCtx { key_id: key_id.clone(), scope: scope.clone() };
                let present = hw.get().key_present(&ctx).map_err(|e| e.to_string());
                Ok(RootReport::Tpm {
                    provider: provider.clone(),
                    key_id: key_id.clone(),
                    scope: scope.clone(),
                    present,
                    has_recovery: h.recovery.is_some(),
                    interrupted_shred: self.pending_path().exists(),
                })
            }
        }
    }

    // --- helpers -------------------------------------------------------------------------------------

    /// Recover the RWK for a hardware vault (via its TPM), or `None` for a software vault.
    fn recover_rwk(&self, h: &Header, passphrase: &[u8]) -> Result<Option<Zeroizing<[u8; RWK_LEN]>>> {
        match &h.root {
            Root::Passphrase => Ok(None),
            Root::TpmPassphrase { provider, scope, key_id, wrapped_rwk } => {
                let _ = passphrase; // RWK comes from hardware, not the passphrase
                let hw = self.hw(provider);
                let ctx = RootCtx { key_id: key_id.clone(), scope: scope.clone() };
                let rwk = hw
                    .get()
                    .unseal_rwk(&ctx, wrapped_rwk)
                    .map_err(|e| anyhow!("hardware key root ({provider}): {e}"))?;
                Ok(Some(rwk))
            }
        }
    }

    /// Build the wrap key from an already-derived KEK (+ optional RWK), for the (possibly just-rebuilt)
    /// root in `h`. Used where the salt/KEK have just been rotated.
    fn wrap_key_from_parts(
        &self,
        h: &Header,
        kek: &[u8; KEY_LEN],
        salt: &[u8],
        rwk: Option<&[u8; RWK_LEN]>,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        match &h.root {
            Root::Passphrase => Ok(Zeroizing::new(*kek)),
            Root::TpmPassphrase { provider, key_id, wrapped_rwk, .. } => {
                let rwk = rwk.ok_or_else(|| anyhow!("hardware vault needs its RWK to re-wrap"))?;
                derive_wrap_key(rwk, kek, salt, h.version, provider, key_id, wrapped_rwk)
            }
        }
    }
}

fn new_id() -> Result<String> {
    Ok(B64.encode(random_bytes::<16>()?).replace(['/', '+', '='], ""))
}

fn mint_key_id() -> Result<String> {
    Ok(format!("SecureDelete-Vault-{}", hex(&random_bytes::<10>()?)))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Mint a recovery code (grouped uppercase hex) and the escrow block sealing `rwk` under it.
fn mint_recovery(rwk: &[u8; RWK_LEN]) -> Result<(String, Recovery)> {
    let raw = Zeroizing::new(random_bytes::<32>()?);
    let code = hex(raw.as_ref())
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
        .to_uppercase();
    let rsalt = random_bytes::<16>()?;
    let rkek = derive_kek(raw.as_ref(), &rsalt, M_COST, T_COST, P_COST)?;
    let sealed_rwk = Vault::seal_with(&rkek, rwk.as_slice(), b"recovery")?;
    Ok((code, Recovery { kdf: Kdf::argon2id(B64.encode(rsalt)), sealed_rwk }))
}

/// Parse a recovery code (any grouping/case) back to its 32 raw bytes.
fn normalize_code(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let hexstr: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hexstr.len() != 64 {
        bail!("recovery code should be 64 hex characters (got {})", hexstr.len());
    }
    let mut out = Vec::with_capacity(32);
    let b = hexstr.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
    }
    Ok(Zeroizing::new(out))
}
