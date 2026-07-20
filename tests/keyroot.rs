//! Key-root tests. The Mock-based logic tests run everywhere; the real-TPM test SKIPS (does not fail)
//! when no usable hardware is present, so CI runners without a TPM stay green.
use secure_delete::keyroot::{KeyRoot, KeyRootError, MockKeyRoot, RootCtx};

#[test]
fn mock_models_a_hardware_crypto_erase() {
    let root = MockKeyRoot::new();
    let ctx = RootCtx::new("vault-A");
    let rwk = [0x11u8; 32];
    let wrapped = root.seal_rwk(&ctx, &rwk).unwrap();
    assert_eq!(*root.unseal_rwk(&ctx, &wrapped).unwrap(), rwk);
    root.destroy(&ctx).unwrap();
    // After destroy the wrapped blob is permanently useless — the hardware guarantee, modelled.
    assert_eq!(root.unseal_rwk(&ctx, &wrapped).unwrap_err(), KeyRootError::KeyNotFound);
}

#[cfg(windows)]
#[test]
fn tpm_seal_unseal_destroy_roundtrip() {
    use secure_delete::keyroot::WindowsTpmRoot;
    if !WindowsTpmRoot::probe() {
        eprintln!("SKIP tpm_seal_unseal_destroy_roundtrip: no usable TPM on this machine");
        return;
    }
    let root = WindowsTpmRoot;
    let ctx = RootCtx::new(format!("SecureDelete-Test-{}", std::process::id()));
    let _ = root.destroy(&ctx); // clean any leftover from a crashed prior run

    let rwk = [0x5au8; 32];
    let wrapped = root.seal_rwk(&ctx, &rwk).expect("seal should succeed on a TPM box");
    assert!(root.key_present(&ctx).unwrap(), "key should exist after seal");

    let got = root.unseal_rwk(&ctx, &wrapped).expect("unseal");
    assert_eq!(*got, rwk, "RWK must round-trip through the TPM");

    // A second seal of the same id is a provisioning collision, not a silent overwrite.
    assert_eq!(root.seal_rwk(&ctx, &rwk).unwrap_err(), KeyRootError::KeyExists);

    // destroy() genuinely evicts the key: unseal is impossible afterwards.
    root.destroy(&ctx).expect("destroy");
    assert!(!root.key_present(&ctx).unwrap(), "key must be gone after destroy");
    assert_eq!(
        root.unseal_rwk(&ctx, &wrapped).unwrap_err(),
        KeyRootError::KeyNotFound,
        "a destroyed TPM key must not unseal"
    );
    let _ = root.destroy(&ctx); // idempotent
}
