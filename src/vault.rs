//! The crypto-erase vault — the SSD solve.
//!
//! Files are encrypted on INGEST (plaintext never lands on flash as a normal file). Each file gets its
//! own random data key (DEK); DEKs live only inside a per-file `meta` blob that is itself encrypted under
//! a random per-vault master key (MK); MK is wrapped under a passphrase-derived KEK (Argon2id) and is
//! never persisted in the clear.
//!
//! To SHRED a file we drop its entry, best-effort-overwrite its ciphertext blob, and then RE-KEY the
//! whole vault: a fresh MK, every surviving meta re-sealed under it, the old MK's only on-disk form
//! (the old wrapped-master + header) overwritten. Any stale copy of the dropped meta the SSD left in
//! flash is now sealed under a dead MK — useless.
//!
//! Honest residual on a commodity SSD (no effaceable hardware): a stale copy of the *old wrapped-master*
//! could linger in flash; recovering a shredded file would require pulling that tiny slot from
//! unaddressable NAND AND knowing the passphrase. Far harder than recovering a plaintext file, but not a
//! hardware-guaranteed zero — a passphrase change (whole-vault re-key) or a TPM-backed root closes it.
use crate::crypto::{aead_decrypt, aead_encrypt, derive_kek, random_bytes, KEY_LEN, NONCE_LEN};
use crate::overwrite::best_effort_overwrite_delete;
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// Argon2id cost defaults (RFC 9106-informed): 64 MiB, 3 passes, 1 lane.
const M_COST: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Kdf {
    alg: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
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

#[derive(Serialize, Deserialize)]
struct Header {
    version: u32,
    kdf: Kdf,
    wrapped_master: Sealed,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    name: String,
    dek: String, // base64 DEK
}

pub struct Vault {
    root: PathBuf,
}

impl Vault {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Vault { root: root.into() }
    }

    fn header_path(&self) -> PathBuf {
        self.root.join("header.json")
    }
    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }
    fn blob_path(&self, id: &str) -> PathBuf {
        self.blobs_dir().join(format!("{id}.bin"))
    }

    fn load(&self) -> Result<Header> {
        let s = fs::read_to_string(self.header_path())
            .context("could not open the vault header (is this a vault directory?)")?;
        Ok(serde_json::from_str(&s)?)
    }

    fn store(&self, h: &Header) -> Result<()> {
        let hp = self.header_path();
        let tmp = self.root.join("header.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(h)?)?;
        if hp.exists() {
            best_effort_overwrite_delete(&hp)?;
        }
        fs::rename(&tmp, &hp)?;
        Ok(())
    }

    fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Sealed> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        let ct = aead_encrypt(key, &nonce, plaintext, b"")?;
        Ok(Sealed {
            nonce: B64.encode(nonce),
            ct: B64.encode(ct),
        })
    }

    fn unseal(key: &[u8; KEY_LEN], s: &Sealed) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = B64
            .decode(&s.nonce)?
            .try_into()
            .map_err(|_| anyhow!("bad nonce length"))?;
        let ct = B64.decode(&s.ct)?;
        aead_decrypt(key, &nonce, &ct, b"")
    }

    fn open_master(&self, h: &Header, passphrase: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let salt = B64.decode(&h.kdf.salt)?;
        let kek = derive_kek(passphrase, &salt, h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost)?;
        let mk_vec = Self::unseal(&kek, &h.wrapped_master)?;
        let mk: [u8; KEY_LEN] = mk_vec
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("corrupt master key"))?;
        Ok(Zeroizing::new(mk))
    }

    /// Create a new empty vault protected by `passphrase`.
    pub fn init(&self, passphrase: &[u8]) -> Result<()> {
        if self.header_path().exists() {
            bail!("a vault already exists at {}", self.root.display());
        }
        fs::create_dir_all(self.blobs_dir())?;
        let salt = random_bytes::<16>()?;
        let kek = derive_kek(passphrase, &salt, M_COST, T_COST, P_COST)?;
        let mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let wrapped_master = Self::seal(&kek, mk.as_ref())?;
        let h = Header {
            version: VERSION,
            kdf: Kdf {
                alg: "argon2id".into(),
                salt: B64.encode(salt),
                m_cost: M_COST,
                t_cost: T_COST,
                p_cost: P_COST,
            },
            wrapped_master,
            entries: vec![],
        };
        self.store(&h)
    }

    /// Encrypt `file` into the vault. Returns its entry id.
    pub fn add(&self, passphrase: &[u8], file: &Path) -> Result<String> {
        let mut h = self.load()?;
        let mk = self.open_master(&h, passphrase)?;
        let data = fs::read(file).with_context(|| format!("read {}", file.display()))?;
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let dek = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let blob_nonce = random_bytes::<NONCE_LEN>()?;
        let blob = aead_encrypt(&dek, &blob_nonce, &data, b"")?;
        let id = B64
            .encode(random_bytes::<16>()?)
            .replace(['/', '+', '='], "");
        fs::create_dir_all(self.blobs_dir())?;
        fs::write(self.blob_path(&id), &blob)?;
        let meta = Meta {
            name,
            dek: B64.encode(dek.as_ref()),
        };
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
        let data = aead_decrypt(&dek, &blob_nonce, &blob, b"")?;
        fs::create_dir_all(out_dir)?;
        let out = out_dir.join(&meta.name);
        fs::write(&out, &data)?;
        Ok(out)
    }

    /// Crypto-erase an entry: drop its key, overwrite its blob, and RE-KEY the whole vault so stale
    /// copies of the dropped meta become useless. See the module docs for the honest SSD residual.
    pub fn shred(&self, passphrase: &[u8], id: &str) -> Result<()> {
        let mut h = self.load()?;
        let old_mk = self.open_master(&h, passphrase)?;
        let pos = h
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or_else(|| anyhow!("no such entry: {id}"))?;

        // Decrypt surviving metas under the OLD master (skip the shredded one).
        let mut survivors: Vec<(Entry, Zeroizing<Vec<u8>>)> = vec![];
        for (i, e) in h.entries.iter().enumerate() {
            if i == pos {
                continue;
            }
            let meta_pt = Zeroizing::new(Self::unseal(&old_mk, &e.meta)?);
            survivors.push((e.clone(), meta_pt));
        }

        // Best-effort-destroy the shredded ciphertext blob.
        let _ = best_effort_overwrite_delete(&self.blob_path(id));

        // RE-KEY: fresh master, re-seal every survivor under it; the old wrapped-master is overwritten by store().
        let salt = B64.decode(&h.kdf.salt)?;
        let kek = derive_kek(passphrase, &salt, h.kdf.m_cost, h.kdf.t_cost, h.kdf.p_cost)?;
        let new_mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let mut new_entries = vec![];
        for (mut e, meta_pt) in survivors {
            e.meta = Self::seal(&new_mk, &meta_pt)?;
            new_entries.push(e);
        }
        h.wrapped_master = Self::seal(&kek, new_mk.as_ref())?;
        h.entries = new_entries;
        self.store(&h)
    }

    /// Re-key the WHOLE vault under a NEW passphrase — a whole-vault crypto-erase. Re-derives the root from the
    /// new passphrase (fresh salt), rotates the master, re-seals every entry, and overwrites the old header. Any
    /// stale copy of the OLD wrapped-master the SSD left in flash becomes useless: decrypting it needs the OLD
    /// passphrase, which is now gone. This is the strong software guarantee (a TPM-sealed root would make it
    /// hardware-certain regardless of whether the old passphrase is known).
    pub fn rekey(&self, old_passphrase: &[u8], new_passphrase: &[u8]) -> Result<()> {
        let mut h = self.load()?;
        let old_mk = self.open_master(&h, old_passphrase)?;
        // decrypt every entry's meta under the old master
        let mut items: Vec<(Entry, Zeroizing<Vec<u8>>)> = vec![];
        for e in &h.entries {
            let pt = Zeroizing::new(Self::unseal(&old_mk, &e.meta)?);
            items.push((e.clone(), pt));
        }
        // new root: fresh salt + KEK from the NEW passphrase; fresh master
        let salt = random_bytes::<16>()?;
        let kek = derive_kek(new_passphrase, &salt, M_COST, T_COST, P_COST)?;
        let new_mk = Zeroizing::new(random_bytes::<KEY_LEN>()?);
        let mut new_entries = vec![];
        for (mut e, pt) in items {
            e.meta = Self::seal(&new_mk, &pt)?;
            new_entries.push(e);
        }
        h.kdf = Kdf {
            alg: "argon2id".into(),
            salt: B64.encode(salt),
            m_cost: M_COST,
            t_cost: T_COST,
            p_cost: P_COST,
        };
        h.wrapped_master = Self::seal(&kek, new_mk.as_ref())?;
        h.entries = new_entries;
        self.store(&h)
    }
}
