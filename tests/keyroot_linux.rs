//! Linux TPM tests via `tpm2-tools`. They SKIP (do not fail) when no TPM2 is reachable; in CI they run
//! against an emulated software TPM (swtpm), so the Linux hardware root is genuinely exercised.
#![cfg(target_os = "linux")]
use secure_delete::keyroot::{KeyRoot, KeyRootError, LinuxTpm2Root, RootCtx};
use secure_delete::Vault;
use std::fs;

const PW: &[u8] = b"linux hardware passphrase";

/// Proceed if a TPM is reachable. Normally SKIP when absent — but if `SD_REQUIRE_TPM=1` (set in CI, where
/// an emulated TPM must be present), a missing TPM is a hard FAILURE so a broken setup can't hide behind a skip.
fn have_tpm() -> bool {
    if LinuxTpm2Root::probe() {
        return true;
    }
    if std::env::var("SD_REQUIRE_TPM").as_deref() == Ok("1") {
        panic!("SD_REQUIRE_TPM=1 but no TPM2 is reachable — the emulated-TPM setup is broken");
    }
    false
}

#[test]
fn linux_tpm_seal_unseal_destroy() {
    if !have_tpm() {
        eprintln!("SKIP linux_tpm_seal_unseal_destroy: no TPM2 reachable");
        return;
    }
    let root = LinuxTpm2Root;
    let ctx = RootCtx::new(format!("SecureDelete-LinuxKR-{}", std::process::id()));
    let _ = root.destroy(&ctx); // clean any leftover

    let rwk = [0x5au8; 32];
    let wrapped = root.seal_rwk(&ctx, &rwk).expect("seal into the TPM");
    assert!(root.key_present(&ctx).unwrap(), "sealed object should be persistent");
    let got = root.unseal_rwk(&ctx, &wrapped).expect("unseal");
    assert_eq!(*got, rwk, "RWK must round-trip through the TPM");

    // Sealing the same id again is a collision (persistent handle already used).
    assert_eq!(root.seal_rwk(&ctx, &rwk).unwrap_err(), KeyRootError::KeyExists);

    // destroy = evict the persistent object -> a TRUE in-hardware erase; unseal then fails.
    root.destroy(&ctx).expect("evict");
    assert!(!root.key_present(&ctx).unwrap());
    assert_eq!(root.unseal_rwk(&ctx, &wrapped).unwrap_err(), KeyRootError::KeyNotFound);
    let _ = root.destroy(&ctx); // idempotent
}

#[test]
fn linux_tpm_vault_end_to_end() {
    if !have_tpm() {
        eprintln!("SKIP linux_tpm_vault_end_to_end: no TPM2 reachable");
        return;
    }
    let tmp = std::env::temp_dir().join(format!("sdlinux-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let f = tmp.join("f");
    fs::write(&f, b"linux hardware secret").unwrap();

    // No injected root -> the real LinuxTpm2Root is used.
    let v = Vault::new(tmp.join("vault"));
    let rep = v.init_tpm(PW, false).unwrap();
    assert_eq!(rep.provider, "tpm2-tools");
    let id = v.add(PW, &f).unwrap();
    assert_eq!(fs::read(v.open(PW, &id, &tmp.join("o")).unwrap()).unwrap(), b"linux hardware secret");

    // Rotate the real TPM key; the file must survive.
    let rep2 = v.hardware_shred(PW, None, false).unwrap();
    assert_ne!(rep2.key_id, rep.key_id, "hardware-shred rotates the TPM object");
    assert!(!v.repair_destroy().unwrap());
    assert_eq!(fs::read(v.open(PW, &id, &tmp.join("o2")).unwrap()).unwrap(), b"linux hardware secret");

    // Clean up the current TPM object this test created.
    let _ = LinuxTpm2Root.destroy(&RootCtx::new(&rep2.key_id));
    let _ = fs::remove_dir_all(&tmp);
}
