//! Pluggable hardware **key root** for the vault.
//!
//! A key root seals a random 32-byte *root-wrapping key* (RWK) so it can only be recovered with the
//! help of a piece of hardware (a TPM / Secure Enclave). The vault combines the recovered RWK with the
//! passphrase-KEK (see [`derive_wrap_key`]) to unwrap the master key — so **both** factors are mandatory.
//!
//! Honesty note (Windows / Microsoft Platform Crypto Provider): `destroy` deletes an SRK-wrapped
//! `.PCPKEY` blob that lives on the *disk* (`%LOCALAPPDATA%\Microsoft\Crypto\PCPKSP`), not inside the
//! TPM's NV storage. The TPM's Storage Root Key never leaves the chip, so a recovered stale blob is only
//! usable on *this* TPM — which defeats a remote "flash image + passphrase" attacker, but is
//! defense-in-depth, **not** an absolute in-hardware erase. We never claim more than that.
//!
//! All OS crypto is reached by shelling out to the platform tool (like `detect.rs`/`status.rs`) so we
//! never pull a `windows-sys`-class dependency (which breaks the gnu build's `dlltool` link).
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
#[cfg(target_os = "linux")]
use sha2::Digest;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const RWK_LEN: usize = 32;

pub const PROVIDER_WINDOWS: &str = "windows-pcp";
pub const PROVIDER_LINUX: &str = "tpm2-tools";
pub const PROVIDER_MACOS: &str = "secure-enclave";
pub const PROVIDER_MOCK: &str = "mock";

/// Identifies a specific sealing key inside a provider. `key_id` is minted at enrollment and stored in
/// the vault header; `scope` is "user" (default, no elevation) or "machine" (admin-provisioned).
#[derive(Debug, Clone)]
pub struct RootCtx {
    pub key_id: String,
    pub scope: String,
}

impl RootCtx {
    pub fn new(key_id: impl Into<String>) -> Self {
        RootCtx { key_id: key_id.into(), scope: "user".into() }
    }
}

/// The distinct failure modes a hardware root can report. Kept separate on purpose: the vault must never
/// collapse "no usable TPM", "key was destroyed", and "wrong passphrase" into one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRootError {
    /// No usable hardware on this machine (provider refused / probe failed). Helper exit 10.
    NoUsableHw,
    /// The named sealing key is gone (moved machine, hardware-shredded, or interrupted rekey). Exit 11.
    KeyNotFound,
    /// The hardware rejected the blob (corrupt / key mismatch / would need UI). Exit 12.
    CryptoFail,
    /// Provisioning collision — a key with this id already exists. Exit 13.
    KeyExists,
    /// The secret we fed the helper was malformed. Exit 20.
    BadInput,
    /// The platform helper itself could not be launched (not installed) — distinct from NoUsableHw.
    ToolUnavailable,
    /// Any other non-zero exit.
    Other(i32),
}

impl KeyRootError {
    /// Map a helper process exit code to an error. Never called with `Some(0)` (that is success).
    pub fn from_exit(code: Option<i32>) -> Self {
        match code {
            Some(10) => KeyRootError::NoUsableHw,
            Some(11) => KeyRootError::KeyNotFound,
            Some(12) => KeyRootError::CryptoFail,
            Some(13) => KeyRootError::KeyExists,
            Some(20) => KeyRootError::BadInput,
            Some(n) => KeyRootError::Other(n),
            None => KeyRootError::Other(-1),
        }
    }
}

impl std::fmt::Display for KeyRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRootError::NoUsableHw => write!(f, "no usable hardware key store on this machine"),
            KeyRootError::KeyNotFound => write!(f, "the vault's hardware sealing key is gone"),
            KeyRootError::CryptoFail => write!(f, "the hardware rejected the sealed key (corrupt or key mismatch)"),
            KeyRootError::KeyExists => write!(f, "a hardware key with this id already exists"),
            KeyRootError::BadInput => write!(f, "malformed input to the hardware helper"),
            KeyRootError::ToolUnavailable => write!(f, "the platform hardware-key helper is not available"),
            KeyRootError::Other(n) => write!(f, "hardware helper failed (exit {n})"),
        }
    }
}
impl std::error::Error for KeyRootError {}

/// Seal / unseal a 32-byte RWK behind a hardware key, and destroy that key.
pub trait KeyRoot {
    /// A stable id for the provider, stored in the vault header (`"windows-pcp"`, `"mock"`, …).
    fn provider_id(&self) -> &'static str;
    /// Seal `rwk` behind the (created-if-absent) hardware key `ctx.key_id`; returns the wrapped blob (b64).
    fn seal_rwk(&self, ctx: &RootCtx, rwk: &[u8; RWK_LEN]) -> Result<String, KeyRootError>;
    /// Recover the RWK from `wrapped` using the hardware key `ctx.key_id`.
    fn unseal_rwk(&self, ctx: &RootCtx, wrapped: &str) -> Result<Zeroizing<[u8; RWK_LEN]>, KeyRootError>;
    /// Destroy the hardware key `ctx.key_id`. Idempotent (absent key = Ok).
    fn destroy(&self, ctx: &RootCtx) -> Result<(), KeyRootError>;
    /// Whether the hardware key `ctx.key_id` currently exists (for `status`, without unsealing).
    fn key_present(&self, ctx: &RootCtx) -> Result<bool, KeyRootError>;
}

/// Combine the hardware RWK with the passphrase KEK into the master-wrapping key (TPM roots only).
///
/// HKDF-SHA256 with the vault salt and an `info` string that binds the vault version, provider, key id,
/// and the wrapped-RWK bytes — so a tampered header (downgrade, cost reduction, blob swap) derives a
/// different key and fails the AEAD tag instead of silently misbehaving. Both inputs are full-entropy and
/// independent, so recovering `wrap_key` needs *both* the TPM (for RWK) and the passphrase (for KEK).
pub fn derive_wrap_key(
    rwk: &[u8; RWK_LEN],
    kek: &[u8; 32],
    salt: &[u8],
    version: u32,
    provider: &str,
    key_id: &str,
    wrapped_rwk: &str,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(RWK_LEN + 32));
    ikm.extend_from_slice(rwk);
    ikm.extend_from_slice(kek);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let ver = version.to_be_bytes();
    let info: [&[u8]; 7] = [
        b"secure-delete/wrap/v2",
        &ver,
        provider.as_bytes(),
        b"\x00",
        key_id.as_bytes(),
        b"\x00",
        wrapped_rwk.as_bytes(),
    ];
    let mut wk = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&info, wk.as_mut())
        .map_err(|_| anyhow::anyhow!("hkdf expand failed"))?;
    Ok(wk)
}

// ---------------------------------------------------------------------------------------------------
// Windows — Microsoft Platform Crypto Provider (TPM-backed RSA), reached via PowerShell.
// ---------------------------------------------------------------------------------------------------

/// TPM-backed key root on Windows via the CNG "Microsoft Platform Crypto Provider" (no `windows-sys`).
#[cfg(windows)]
pub struct WindowsTpmRoot;

#[cfg(windows)]
const PS_PREAMBLE: &str = r#"$ErrorActionPreference='Stop'; Set-StrictMode -Version Latest
$name = $env:SD_KEY_ID
if ([string]::IsNullOrWhiteSpace($name)) { [Console]::Error.WriteLine('SD_KEY_ID missing'); exit 20 }
$prov = [System.Security.Cryptography.CngProvider]::new('Microsoft Platform Crypto Provider')
$mach = ($env:SD_SCOPE -eq 'machine')
$oo = if ($mach) { [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey } else { [System.Security.Cryptography.CngKeyOpenOptions]::None }
$oaep = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
function New-PcpKey($kn) {
  $cp = [System.Security.Cryptography.CngKeyCreationParameters]::new()
  $cp.Provider = $prov
  $cp.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
  if ($mach) { $cp.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey }
  $cp.Parameters.Add([System.Security.Cryptography.CngProperty]::new('Length', [BitConverter]::GetBytes([int]2048), [System.Security.Cryptography.CngPropertyOptions]::None))
  [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $kn, $cp)
}"#;

#[cfg(windows)]
const PS_SEAL: &str = r#"try {
  $exists = [System.Security.Cryptography.CngKey]::Exists($name, $prov, $oo)
  if ($exists -and $env:SD_ALLOW_EXISTING -ne '1') { [Console]::Error.WriteLine('key-exists'); exit 13 }
  if ($exists) { $key = [System.Security.Cryptography.CngKey]::Open($name, $prov, $oo) } else { $key = New-PcpKey $name }
  $rsa = [System.Security.Cryptography.RSACng]::new($key)
  $probe = New-Object byte[] 32
  $c0 = $rsa.Encrypt($probe, $oaep); $p0 = $rsa.Decrypt($c0, $oaep)
  if (@(Compare-Object $probe $p0 -SyncWindow 0).Count -ne 0) { [Console]::Error.WriteLine('selftest-fail'); exit 12 }
  $b64 = [Console]::In.ReadLine()
  $secret = [Convert]::FromBase64String($b64)
  if ($secret.Length -ne 32) { [Console]::Error.WriteLine('bad-input-len'); exit 20 }
  $ct = $rsa.Encrypt($secret, $oaep)
  [Array]::Clear($secret, 0, $secret.Length)
  Write-Output ([Convert]::ToBase64String($ct)); exit 0
} catch { [Console]::Error.WriteLine("seal: $($_.Exception.Message)"); exit 10 }"#;

#[cfg(windows)]
const PS_UNSEAL: &str = r#"try {
  if (-not [System.Security.Cryptography.CngKey]::Exists($name, $prov, $oo)) { [Console]::Error.WriteLine('key-not-found'); exit 11 }
  $key = [System.Security.Cryptography.CngKey]::Open($name, $prov, $oo)
  $b64 = [Console]::In.ReadLine()
  $ct = [Convert]::FromBase64String($b64)
  $rsa = [System.Security.Cryptography.RSACng]::new($key)
  $pt = $rsa.Decrypt($ct, $oaep)
  if ($pt.Length -ne 32) { [Console]::Error.WriteLine('bad-length'); exit 12 }
  $out = [Convert]::ToBase64String($pt)
  [Array]::Clear($pt, 0, $pt.Length)
  Write-Output $out; exit 0
} catch { [Console]::Error.WriteLine("unseal: $($_.Exception.Message)"); exit 12 }"#;

#[cfg(windows)]
const PS_DESTROY: &str = r#"try {
  if (-not [System.Security.Cryptography.CngKey]::Exists($name, $prov, $oo)) { Write-Output 'ABSENT'; exit 0 }
  [System.Security.Cryptography.CngKey]::Open($name, $prov, $oo).Delete()
  if ([System.Security.Cryptography.CngKey]::Exists($name, $prov, $oo)) { [Console]::Error.WriteLine('still-present'); exit 1 }
  Write-Output 'DELETED'; exit 0
} catch { [Console]::Error.WriteLine("destroy: $($_.Exception.Message)"); exit 1 }"#;

#[cfg(windows)]
const PS_PRESENT: &str = r#"if ([System.Security.Cryptography.CngKey]::Exists($name, $prov, $oo)) { Write-Output 'PRESENT'; exit 0 } else { Write-Output 'ABSENT'; exit 11 }"#;

#[cfg(windows)]
const PS_PROBE: &str = r#"$pn = 'SecureDelete-Probe-' + [Guid]::NewGuid().ToString('N')
try {
  $key = New-PcpKey $pn
  $rsa = [System.Security.Cryptography.RSACng]::new($key)
  $b = New-Object byte[] 32
  $ct = $rsa.Encrypt($b, $oaep); $pt = $rsa.Decrypt($ct, $oaep)
  $ok = (@(Compare-Object $b $pt -SyncWindow 0).Count -eq 0)
  $key.Delete()
  if ($ok) { Write-Output 'TPM_USABLE'; exit 0 } else { [Console]::Error.WriteLine('roundtrip-mismatch'); exit 10 }
} catch {
  try { if ([System.Security.Cryptography.CngKey]::Exists($pn, $prov, $oo)) { [System.Security.Cryptography.CngKey]::Open($pn, $prov, $oo).Delete() } } catch {}
  [Console]::Error.WriteLine("probe: $($_.Exception.Message)"); exit 10
}"#;

/// Base64(UTF-16LE) for `powershell -EncodedCommand` — the script carries no secret, so even full
/// ScriptBlock/transcription logging can never capture the RWK (which travels only on stdin).
#[cfg(windows)]
fn ps_encoded(script: &str) -> String {
    let u16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    B64.encode(u16)
}

/// Run one PowerShell op: script via `-EncodedCommand`, non-secret ids via env, the secret via stdin.
/// Returns (exit_code, stdout_trimmed, stderr_trimmed).
#[cfg(windows)]
fn run_ps(body: &str, ctx: &RootCtx, stdin_b64: Option<&str>) -> Result<(i32, String, String), KeyRootError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let full = format!("{PS_PREAMBLE}\n{body}");
    let enc = ps_encoded(&full);
    let mut child = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &enc])
        .env("SD_KEY_ID", &ctx.key_id)
        .env("SD_SCOPE", &ctx.scope)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| KeyRootError::ToolUnavailable)?;
    {
        // Always take + close stdin; write the secret first if present, then drop to send EOF.
        let mut si = child.stdin.take().ok_or(KeyRootError::ToolUnavailable)?;
        if let Some(s) = stdin_b64 {
            let _ = writeln!(si, "{s}");
        }
    }
    let out = child.wait_with_output().map_err(|_| KeyRootError::ToolUnavailable)?;
    Ok((
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

#[cfg(windows)]
impl WindowsTpmRoot {
    /// Authoritative "is a usable TPM present for this user?" — an ephemeral create+roundtrip+delete
    /// (NOT `Get-Tpm`, which needs admin and reports chip state, not per-user usability).
    pub fn probe() -> bool {
        let ctx = RootCtx::new("SecureDelete-Probe");
        matches!(run_ps(PS_PROBE, &ctx, None), Ok((0, _, _)))
    }
}

#[cfg(windows)]
impl KeyRoot for WindowsTpmRoot {
    fn provider_id(&self) -> &'static str {
        PROVIDER_WINDOWS
    }
    fn seal_rwk(&self, ctx: &RootCtx, rwk: &[u8; RWK_LEN]) -> Result<String, KeyRootError> {
        let b64 = Zeroizing::new(B64.encode(rwk));
        match run_ps(PS_SEAL, ctx, Some(&b64))? {
            (0, out, _) if !out.is_empty() => Ok(out),
            (0, _, _) => Err(KeyRootError::Other(0)),
            (code, _, _) => Err(KeyRootError::from_exit(Some(code))),
        }
    }
    fn unseal_rwk(&self, ctx: &RootCtx, wrapped: &str) -> Result<Zeroizing<[u8; RWK_LEN]>, KeyRootError> {
        let (code, out, _err) = run_ps(PS_UNSEAL, ctx, Some(wrapped))?;
        if code != 0 {
            return Err(KeyRootError::from_exit(Some(code)));
        }
        let bytes = Zeroizing::new(B64.decode(out.as_bytes()).map_err(|_| KeyRootError::CryptoFail)?);
        let arr: [u8; RWK_LEN] = bytes.as_slice().try_into().map_err(|_| KeyRootError::CryptoFail)?;
        Ok(Zeroizing::new(arr))
    }
    fn destroy(&self, ctx: &RootCtx) -> Result<(), KeyRootError> {
        match run_ps(PS_DESTROY, ctx, None)? {
            (0, _, _) => Ok(()),
            (code, _, _) => Err(KeyRootError::from_exit(Some(code))),
        }
    }
    fn key_present(&self, ctx: &RootCtx) -> Result<bool, KeyRootError> {
        match run_ps(PS_PRESENT, ctx, None)? {
            (0, _, _) => Ok(true),
            (11, _, _) => Ok(false),
            (code, _, _) => Err(KeyRootError::from_exit(Some(code))),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Linux — a TPM 2.0 via `tpm2-tools`. The RWK is sealed into a PERSISTENT keyedhash object and the
// object is evicted on destroy — a TRUE in-hardware erase (the RWK lives only in TPM NV, never wrapped
// on disk). Transient context/blob files go in /dev/shm (RAM) so they never land on the SSD.
// ---------------------------------------------------------------------------------------------------

/// TPM-backed key root on Linux via `tpm2-tools` (shell-out, no `windows-sys`-class dependency).
#[cfg(target_os = "linux")]
pub struct LinuxTpm2Root;

#[cfg(target_os = "linux")]
fn hexs(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[cfg(target_os = "linux")]
fn tpm2(args: &[&str], stdin: Option<&[u8]>) -> Result<(i32, Vec<u8>, String), KeyRootError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| KeyRootError::ToolUnavailable)?;
    {
        let mut si = child.stdin.take().ok_or(KeyRootError::ToolUnavailable)?;
        if let Some(b) = stdin {
            let _ = si.write_all(b);
        }
    }
    let out = child.wait_with_output().map_err(|_| KeyRootError::ToolUnavailable)?;
    Ok((out.status.code().unwrap_or(-1), out.stdout, String::from_utf8_lossy(&out.stderr).into_owned()))
}

/// Run a tpm2 command, mapping a non-zero exit to an error and surfacing its stderr (useful for real
/// users debugging a TPM too).
#[cfg(target_os = "linux")]
fn tpm2_ok(args: &[&str], stdin: Option<&[u8]>) -> Result<(), KeyRootError> {
    let (code, _out, err) = tpm2(args, stdin)?;
    if code == 0 {
        Ok(())
    } else {
        eprintln!("secure-delete: tpm2 `{}` failed (exit {code}): {}", args.join(" "), err.trim());
        Err(KeyRootError::CryptoFail)
    }
}

#[cfg(target_os = "linux")]
impl LinuxTpm2Root {
    /// Shared persistent storage-root key (the standard SRK handle). Using a PERSISTENT parent means no
    /// transient primary is ever left loaded — which matters when no resource manager is flushing them.
    const SRK: &'static str = "0x81000001";

    /// Create the persistent SRK once (idempotent, tolerant of a concurrent creator).
    fn ensure_srk() -> Result<(), KeyRootError> {
        if Self::is_persistent(Self::SRK) {
            return Ok(());
        }
        let wd = Self::work_dir()?;
        let pctx = wd.join("primary.ctx").to_string_lossy().into_owned();
        let mut created = tpm2_ok(&["tpm2_createprimary", "-C", "o", "-c", &pctx], None);
        if created.is_ok() {
            created = tpm2_ok(&["tpm2_evictcontrol", "-C", "o", "-c", &pctx, Self::SRK], None);
        }
        let _ = tpm2(&["tpm2_flushcontext", &pctx], None); // never leak the transient primary
        let _ = std::fs::remove_dir_all(&wd);
        if Self::is_persistent(Self::SRK) {
            Ok(()) // someone (maybe us) made it
        } else {
            created
        }
    }

    /// A usable TPM 2.0 is present iff `tpm2_getcap` talks to it.
    pub fn probe() -> bool {
        matches!(tpm2(&["tpm2_getcap", "properties-fixed"], None), Ok((0, _, _)))
    }

    /// Deterministic persistent handle in the owner range (0x8101_0000..=0x8101_ffff) from the key id.
    fn handle(key_id: &str) -> String {
        let mut h = Sha256::new();
        h.update(key_id.as_bytes());
        let d = h.finalize();
        let off = ((d[0] as u16) << 8) | d[1] as u16;
        format!("0x8101{off:04x}")
    }

    fn is_persistent(handle: &str) -> bool {
        match tpm2(&["tpm2_getcap", "handles-persistent"], None) {
            Ok((0, out, _)) => String::from_utf8_lossy(&out).to_lowercase().contains(&handle.to_lowercase()),
            _ => false,
        }
    }

    /// A RAM-backed work dir (so transient TPM blobs never hit the SSD), removed by the caller.
    fn work_dir() -> Result<std::path::PathBuf, KeyRootError> {
        let base = if std::path::Path::new("/dev/shm").is_dir() {
            std::path::PathBuf::from("/dev/shm")
        } else {
            std::env::temp_dir()
        };
        let r = crate::crypto::random_bytes::<8>().map_err(|_| KeyRootError::Other(1))?;
        let d = base.join(format!("secure-delete-tpm-{}", hexs(&r)));
        std::fs::create_dir(&d).map_err(|_| KeyRootError::Other(2))?;
        Ok(d)
    }
}

#[cfg(target_os = "linux")]
impl KeyRoot for LinuxTpm2Root {
    fn provider_id(&self) -> &'static str {
        PROVIDER_LINUX
    }
    fn seal_rwk(&self, ctx: &RootCtx, rwk: &[u8; RWK_LEN]) -> Result<String, KeyRootError> {
        let handle = Self::handle(&ctx.key_id);
        if Self::is_persistent(&handle) {
            return Err(KeyRootError::KeyExists);
        }
        Self::ensure_srk()?;
        let wd = Self::work_dir()?;
        let path = |n: &str| wd.join(n).to_string_lossy().into_owned();
        let (spub, spriv, sctx) = (path("seal.pub"), path("seal.priv"), path("seal.ctx"));
        // Seal the RWK under the PERSISTENT SRK. Only the sealed object is transient (during load); it is
        // flushed after we persist it, so nothing accumulates even without a resource manager.
        let result = (|| {
            tpm2_ok(&["tpm2_create", "-C", Self::SRK, "-u", &spub, "-r", &spriv, "-i", "-"], Some(rwk))?;
            tpm2_ok(&["tpm2_load", "-C", Self::SRK, "-u", &spub, "-r", &spriv, "-c", &sctx], None)?;
            tpm2_ok(&["tpm2_evictcontrol", "-C", "o", "-c", &sctx, &handle], None)?;
            Ok(())
        })();
        let _ = tpm2(&["tpm2_flushcontext", &sctx], None); // flush the transient sealed object
        let _ = std::fs::remove_dir_all(&wd);
        result.map(|_| String::new()) // RWK lives in the TPM; nothing to store on disk.
    }
    fn unseal_rwk(&self, ctx: &RootCtx, _wrapped: &str) -> Result<Zeroizing<[u8; RWK_LEN]>, KeyRootError> {
        let handle = Self::handle(&ctx.key_id);
        if !Self::is_persistent(&handle) {
            return Err(KeyRootError::KeyNotFound);
        }
        let (code, out, _e) = tpm2(&["tpm2_unseal", "-c", &handle], None)?;
        if code != 0 {
            return Err(KeyRootError::CryptoFail);
        }
        if out.len() != RWK_LEN {
            return Err(KeyRootError::CryptoFail);
        }
        let mut arr = [0u8; RWK_LEN];
        arr.copy_from_slice(&out[..RWK_LEN]);
        Ok(Zeroizing::new(arr))
    }
    fn destroy(&self, ctx: &RootCtx) -> Result<(), KeyRootError> {
        let handle = Self::handle(&ctx.key_id);
        if !Self::is_persistent(&handle) {
            return Ok(()); // idempotent
        }
        match tpm2(&["tpm2_evictcontrol", "-C", "o", "-c", &handle], None)? {
            (0, _, _) => Ok(()),
            (code, _, _) => Err(KeyRootError::Other(code)),
        }
    }
    fn key_present(&self, ctx: &RootCtx) -> Result<bool, KeyRootError> {
        Ok(Self::is_persistent(&Self::handle(&ctx.key_id)))
    }
}

// ---------------------------------------------------------------------------------------------------
// Other non-Windows/Linux providers (notably macOS Secure Enclave) — honest stubs for now. macOS needs
// a signed Swift Security.framework helper (SE keys are EC-P256, wrap via ECIES) + real Apple silicon to
// build/test, so it reports "unavailable" rather than shipping an unverifiable path.
// ---------------------------------------------------------------------------------------------------

/// A key root whose provider isn't implemented/usable on this build. Honest by construction.
pub struct UnavailableRoot(pub &'static str);

impl KeyRoot for UnavailableRoot {
    fn provider_id(&self) -> &'static str {
        self.0
    }
    fn seal_rwk(&self, _c: &RootCtx, _r: &[u8; RWK_LEN]) -> Result<String, KeyRootError> {
        Err(KeyRootError::ToolUnavailable)
    }
    fn unseal_rwk(&self, _c: &RootCtx, _w: &str) -> Result<Zeroizing<[u8; RWK_LEN]>, KeyRootError> {
        Err(KeyRootError::ToolUnavailable)
    }
    fn destroy(&self, _c: &RootCtx) -> Result<(), KeyRootError> {
        Err(KeyRootError::ToolUnavailable)
    }
    fn key_present(&self, _c: &RootCtx) -> Result<bool, KeyRootError> {
        Err(KeyRootError::ToolUnavailable)
    }
}

/// Build the platform key root for a header `provider` string. Unknown/unbuilt providers return an
/// [`UnavailableRoot`] so open/status fail loudly rather than degrading to software.
pub fn root_for_provider(provider: &str) -> Box<dyn KeyRoot> {
    match provider {
        #[cfg(windows)]
        PROVIDER_WINDOWS => Box::new(WindowsTpmRoot),
        #[cfg(target_os = "linux")]
        PROVIDER_LINUX => Box::new(LinuxTpm2Root),
        _ => Box::new(UnavailableRoot(provider_static(provider))),
    }
}

/// The default hardware provider id for the current platform (what `init --tpm` enrolls).
pub fn default_provider() -> &'static str {
    #[cfg(windows)]
    {
        PROVIDER_WINDOWS
    }
    #[cfg(target_os = "linux")]
    {
        PROVIDER_LINUX
    }
    #[cfg(target_os = "macos")]
    {
        PROVIDER_MACOS
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        "none"
    }
}

/// Is a usable hardware key store available on this machine right now?
pub fn hardware_available() -> bool {
    #[cfg(windows)]
    {
        WindowsTpmRoot::probe()
    }
    #[cfg(target_os = "linux")]
    {
        LinuxTpm2Root::probe()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

/// Intern a provider string to `'static` for [`UnavailableRoot`]. Known names map to their constant;
/// anything else falls back to a generic label (its exact text is only informational).
fn provider_static(p: &str) -> &'static str {
    match p {
        PROVIDER_WINDOWS => PROVIDER_WINDOWS,
        PROVIDER_LINUX => PROVIDER_LINUX,
        PROVIDER_MACOS => PROVIDER_MACOS,
        PROVIDER_MOCK => PROVIDER_MOCK,
        _ => "unknown-provider",
    }
}

// ---------------------------------------------------------------------------------------------------
// MockKeyRoot — in-process "hardware" for testing header/combiner/ordering logic with zero real TPM.
// ---------------------------------------------------------------------------------------------------

/// An in-memory key root for tests. Each `key_id` maps to a random 32-byte "hardware key"; `destroy`
/// forgets it so later `unseal` fails with `KeyNotFound` — modelling a real hardware crypto-erase.
pub struct MockKeyRoot {
    keys: std::sync::Mutex<std::collections::HashMap<String, [u8; RWK_LEN]>>,
}

impl Default for MockKeyRoot {
    fn default() -> Self {
        MockKeyRoot { keys: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }
}

impl MockKeyRoot {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyRoot for MockKeyRoot {
    fn provider_id(&self) -> &'static str {
        PROVIDER_MOCK
    }
    fn seal_rwk(&self, ctx: &RootCtx, rwk: &[u8; RWK_LEN]) -> Result<String, KeyRootError> {
        let mut g = self.keys.lock().unwrap();
        if g.contains_key(&ctx.key_id) {
            return Err(KeyRootError::KeyExists);
        }
        let hk = crate::crypto::random_bytes::<RWK_LEN>().map_err(|_| KeyRootError::Other(1))?;
        let mut wrapped = [0u8; RWK_LEN];
        for i in 0..RWK_LEN {
            wrapped[i] = rwk[i] ^ hk[i];
        }
        g.insert(ctx.key_id.clone(), hk);
        Ok(B64.encode(wrapped))
    }
    fn unseal_rwk(&self, ctx: &RootCtx, wrapped: &str) -> Result<Zeroizing<[u8; RWK_LEN]>, KeyRootError> {
        let g = self.keys.lock().unwrap();
        let hk = g.get(&ctx.key_id).ok_or(KeyRootError::KeyNotFound)?;
        let w = B64.decode(wrapped.as_bytes()).map_err(|_| KeyRootError::CryptoFail)?;
        let w: [u8; RWK_LEN] = w.as_slice().try_into().map_err(|_| KeyRootError::CryptoFail)?;
        let mut rwk = [0u8; RWK_LEN];
        for i in 0..RWK_LEN {
            rwk[i] = w[i] ^ hk[i];
        }
        Ok(Zeroizing::new(rwk))
    }
    fn destroy(&self, ctx: &RootCtx) -> Result<(), KeyRootError> {
        self.keys.lock().unwrap().remove(&ctx.key_id);
        Ok(())
    }
    fn key_present(&self, ctx: &RootCtx) -> Result<bool, KeyRootError> {
        Ok(self.keys.lock().unwrap().contains_key(&ctx.key_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combiner_is_deterministic_and_binds_info() {
        let rwk = [7u8; RWK_LEN];
        let kek = [9u8; 32];
        let salt = b"salt-salt-salt00";
        let a = derive_wrap_key(&rwk, &kek, salt, 2, "windows-pcp", "k1", "blob").unwrap();
        let b = derive_wrap_key(&rwk, &kek, salt, 2, "windows-pcp", "k1", "blob").unwrap();
        assert_eq!(*a, *b, "same inputs -> same key");
        // Any bound field change -> different key.
        let c = derive_wrap_key(&rwk, &kek, salt, 2, "windows-pcp", "k2", "blob").unwrap();
        assert_ne!(*a, *c, "key_id is bound");
        let d = derive_wrap_key(&rwk, &kek, salt, 3, "windows-pcp", "k1", "blob").unwrap();
        assert_ne!(*a, *d, "version is bound");
        // Either secret factor changing -> different key (both mandatory).
        let e = derive_wrap_key(&[8u8; RWK_LEN], &kek, salt, 2, "windows-pcp", "k1", "blob").unwrap();
        assert_ne!(*a, *e, "RWK is mandatory");
        let f = derive_wrap_key(&rwk, &[1u8; 32], salt, 2, "windows-pcp", "k1", "blob").unwrap();
        assert_ne!(*a, *f, "KEK is mandatory");
    }

    #[test]
    fn mock_seal_unseal_roundtrip_and_destroy() {
        let mk = MockKeyRoot::new();
        let ctx = RootCtx::new("vault-1");
        let rwk = [42u8; RWK_LEN];
        let wrapped = mk.seal_rwk(&ctx, &rwk).unwrap();
        assert!(mk.key_present(&ctx).unwrap());
        let got = mk.unseal_rwk(&ctx, &wrapped).unwrap();
        assert_eq!(*got, rwk);
        // Sealing the same id twice is a collision.
        assert_eq!(mk.seal_rwk(&ctx, &rwk).unwrap_err(), KeyRootError::KeyExists);
        // Destroy = crypto-erase: the wrapped blob is now useless.
        mk.destroy(&ctx).unwrap();
        assert!(!mk.key_present(&ctx).unwrap());
        assert_eq!(mk.unseal_rwk(&ctx, &wrapped).unwrap_err(), KeyRootError::KeyNotFound);
        // Destroy is idempotent.
        mk.destroy(&ctx).unwrap();
    }
}
