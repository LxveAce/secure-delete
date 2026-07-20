//! Hardware-rooted vault tests, driven by an in-process `MockKeyRoot` so they run on CI with no TPM.
//! They exercise the logic the red-team flagged: no silent software fallback, AAD/downgrade rejection,
//! the shred vs hardware-shred split, and recovery-kit round-trips.
use secure_delete::keyroot::MockKeyRoot;
use secure_delete::vault::RootReport;
use secure_delete::Vault;
use std::fs;
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sdtpm-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn mock_vault(dir: PathBuf) -> Vault {
    Vault::with_key_root(dir, Box::new(MockKeyRoot::new()))
}

const PW: &[u8] = b"correct horse battery";

#[test]
fn software_header_stays_byte_identical() {
    // A software vault must NOT gain any of the new header keys — old tools + old vaults keep working.
    let tmp = scratch("soft");
    let vdir = tmp.join("vault");
    Vault::new(&vdir).init(PW).unwrap();
    let hdr = fs::read_to_string(vdir.join("header.json")).unwrap();
    assert!(!hdr.contains("\"root\""), "software header must omit `root`");
    assert!(!hdr.contains("kind"), "software header must omit the root tag");
    assert!(!hdr.contains("recovery"), "software header must omit `recovery`");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn reject_future_version() {
    let tmp = scratch("ver");
    let vdir = tmp.join("vault");
    let v = Vault::new(&vdir);
    v.init(PW).unwrap();
    let hp = vdir.join("header.json");
    let bumped = fs::read_to_string(&hp).unwrap().replace("\"version\": 1", "\"version\": 99");
    fs::write(&hp, bumped).unwrap();
    let err = v.list(PW).unwrap_err().to_string();
    assert!(err.contains("newer secure-delete"), "got: {err}");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_init_add_open_roundtrip_with_recovery() {
    let tmp = scratch("rt");
    let src = tmp.join("s.txt");
    fs::write(&src, b"hardware-guarded secret").unwrap();
    let v = mock_vault(tmp.join("vault"));
    let rep = v.init_tpm(PW, false).unwrap();
    assert_eq!(rep.provider, "mock");
    assert!(rep.recovery_code.is_some(), "a recovery kit must be minted by default");
    let id = v.add(PW, &src).unwrap();
    assert_eq!(v.list(PW).unwrap().len(), 1);
    let out = v.open(PW, &id, &tmp.join("out")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"hardware-guarded secret");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_wrong_passphrase_reads_as_passphrase_not_hardware() {
    let tmp = scratch("wp");
    let src = tmp.join("s.txt");
    fs::write(&src, b"x").unwrap();
    let v = mock_vault(tmp.join("vault"));
    v.init_tpm(PW, false).unwrap();
    let id = v.add(PW, &src).unwrap();
    // Hardware is present (mock has the key); a wrong passphrase must fail as a passphrase error.
    let err = v.open(b"WRONG", &id, &tmp.join("out")).unwrap_err().to_string();
    assert!(err.contains("passphrase"), "wrong pass should be a passphrase error, got: {err}");
    assert!(!err.contains("hardware key root"), "must not be misattributed to hardware: {err}");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_missing_hardware_fails_loudly_no_software_fallback() {
    let tmp = scratch("nohw");
    let src = tmp.join("s.txt");
    fs::write(&src, b"x").unwrap();
    // Enroll with one mock "TPM", then try to open with a FRESH, empty mock (simulates another machine).
    let vdir = tmp.join("vault");
    mock_vault(vdir.clone()).init_tpm(PW, false).unwrap();
    let v2 = mock_vault(vdir.clone());
    let _ = v2.add(PW, &src); // may fail; we only care about the open below
    let err = v2.list(PW).unwrap_err().to_string();
    assert!(err.contains("hardware key root"), "must fail as a hardware error, got: {err}");
    assert!(!err.contains("wrong passphrase"), "must NOT degrade to a passphrase/software path: {err}");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_header_downgrade_is_rejected() {
    let tmp = scratch("dg");
    let vdir = tmp.join("vault");
    let v = mock_vault(vdir.clone());
    v.init_tpm(PW, false).unwrap();
    // Attacker rewrites the header to claim a software root, hoping open() uses the passphrase alone.
    let hp = vdir.join("header.json");
    let tampered = fs::read_to_string(&hp).unwrap().replace("tpm+passphrase", "passphrase");
    fs::write(&hp, tampered).unwrap();
    // The master was sealed under HKDF(RWK||KEK) with a bound AAD; the software path derives a different
    // key and fails the AEAD tag instead of opening.
    assert!(v.list(PW).is_err(), "a downgraded header must not open");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_shred_keeps_the_hardware_key() {
    let tmp = scratch("shred");
    let f1 = tmp.join("one");
    let f2 = tmp.join("two");
    fs::write(&f1, b"one").unwrap();
    fs::write(&f2, b"two").unwrap();
    let v = mock_vault(tmp.join("vault"));
    let rep = v.init_tpm(PW, false).unwrap();
    let id1 = v.add(PW, &f1).unwrap();
    let _id2 = v.add(PW, &f2).unwrap();

    v.shred(PW, &id1).unwrap();
    assert!(v.open(PW, &id1, &tmp.join("o")).is_err(), "shredded file is gone");
    assert_eq!(v.list(PW).unwrap().len(), 1, "survivor remains");
    // Routine shred must NOT rotate the TPM key.
    match v.root_report().unwrap() {
        RootReport::Tpm { key_id, present, .. } => {
            assert_eq!(key_id, rep.key_id, "shred must not rotate the TPM key");
            assert!(present.unwrap(), "TPM key still present after shred");
        }
        _ => panic!("expected a TPM root"),
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_rekey_keeps_hardware_key_and_recovery() {
    let tmp = scratch("rekey");
    let f = tmp.join("f");
    fs::write(&f, b"payload").unwrap();
    let v = mock_vault(tmp.join("vault"));
    let rep = v.init_tpm(PW, false).unwrap();
    let id = v.add(PW, &f).unwrap();

    v.rekey(PW, b"new-pass-phrase").unwrap();
    assert!(v.open(PW, &id, &tmp.join("o")).is_err(), "old passphrase must die");
    let out = v.open(b"new-pass-phrase", &id, &tmp.join("o")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"payload");
    match v.root_report().unwrap() {
        RootReport::Tpm { key_id, has_recovery, .. } => {
            assert_eq!(key_id, rep.key_id, "rekey keeps the same RWK/TPM key");
            assert!(has_recovery, "recovery kit survives rekey");
        }
        _ => panic!("expected a TPM root"),
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_hardware_shred_rotates_the_key() {
    let tmp = scratch("hwshred");
    let f = tmp.join("f");
    fs::write(&f, b"payload").unwrap();
    let v = mock_vault(tmp.join("vault"));
    let rep0 = v.init_tpm(PW, false).unwrap();
    let id = v.add(PW, &f).unwrap();

    let rep1 = v.hardware_shred(PW, None, false).unwrap();
    assert_ne!(rep1.key_id, rep0.key_id, "hardware-shred rotates the TPM key");
    assert!(rep1.recovery_code.is_some(), "recovery kit is re-minted");
    assert_ne!(rep1.recovery_code, rep0.recovery_code, "a fresh recovery code");
    // Still opens with the passphrase; the file survives; no interrupted-shred marker remains.
    let out = v.open(PW, &id, &tmp.join("o")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"payload");
    assert!(!v.repair_destroy().unwrap(), "no pending destroy left behind");
    match v.root_report().unwrap() {
        RootReport::Tpm { key_id, interrupted_shred, .. } => {
            assert_eq!(key_id, rep1.key_id);
            assert!(!interrupted_shred);
        }
        _ => panic!("expected a TPM root"),
    }
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_recover_reprovisions_on_fresh_hardware() {
    let tmp = scratch("recov");
    let f = tmp.join("f");
    fs::write(&f, b"payload").unwrap();
    let vdir = tmp.join("vault");
    // Enroll on "machine 1" (its mock holds the key).
    let code = mock_vault(vdir.clone()).init_tpm(PW, false).unwrap().recovery_code.unwrap();

    // "Machine 2": a brand-new empty mock -> the vault's original key is absent.
    let vnew = mock_vault(vdir.clone());
    assert!(vnew.list(PW).is_err(), "without the original TPM the vault can't open");

    // Recover: re-provision a fresh hardware key from the recovery code + passphrase.
    let rep = vnew.recover(&code, PW, false).unwrap();
    assert!(rep.recovery_code.is_some(), "recovery re-mints a kit");
    // Now the same vnew (its mock now holds the new key) opens and can take files.
    let id = vnew.add(PW, &f).unwrap();
    let out = vnew.open(PW, &id, &tmp.join("o")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"payload");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_recover_to_software_downgrades_cleanly() {
    let tmp = scratch("tosoft");
    let f = tmp.join("f");
    fs::write(&f, b"payload").unwrap();
    let vdir = tmp.join("vault");
    let venroll = mock_vault(vdir.clone());
    let code = venroll.init_tpm(PW, false).unwrap().recovery_code.unwrap();
    let id = venroll.add(PW, &f).unwrap();

    // Convert to a software vault using the recovery code + passphrase.
    let vnew = mock_vault(vdir.clone());
    vnew.recover(&code, PW, true).unwrap();

    // A plain vault with NO key root now opens it with the passphrase alone.
    let plain = Vault::new(&vdir);
    let out = plain.open(PW, &id, &tmp.join("o")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"payload");
    let hdr = fs::read_to_string(vdir.join("header.json")).unwrap();
    assert!(!hdr.contains("kind"), "downgraded header must be a clean software header");
    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(windows)]
#[test]
fn real_tpm_end_to_end() {
    use secure_delete::keyroot::{hardware_available, KeyRoot, RootCtx, WindowsTpmRoot};
    if !hardware_available() {
        eprintln!("SKIP real_tpm_end_to_end: no usable TPM on this machine");
        return;
    }
    let tmp = scratch("real");
    let f = tmp.join("f");
    fs::write(&f, b"real hardware secret").unwrap();
    // No injected root -> the real WindowsTpmRoot is used.
    let v = Vault::new(tmp.join("vault"));
    let rep = v.init_tpm(PW, false).unwrap();
    assert_eq!(rep.provider, "windows-pcp");
    let id = v.add(PW, &f).unwrap();
    let out = v.open(PW, &id, &tmp.join("o")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"real hardware secret");

    // Rotate the real TPM key; the file must survive and no pending marker may remain.
    let rep2 = v.hardware_shred(PW, None, false).unwrap();
    assert_ne!(rep2.key_id, rep.key_id, "the real TPM key was rotated");
    assert!(!v.repair_destroy().unwrap());
    let out2 = v.open(PW, &id, &tmp.join("o2")).unwrap();
    assert_eq!(fs::read(&out2).unwrap(), b"real hardware secret");

    // Clean up the TPM key this test created (avoid orphaned .PCPKEY blobs).
    let _ = WindowsTpmRoot.destroy(&RootCtx::new(&rep2.key_id));
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn tpm_skip_recovery_has_no_kit() {
    let tmp = scratch("norec");
    let v = mock_vault(tmp.join("vault"));
    let rep = v.init_tpm(PW, true).unwrap();
    assert!(rep.recovery_code.is_none(), "--i-understand-total-loss mints no code");
    assert!(v.recover("0000", PW, false).is_err(), "no kit -> recover refuses");
    let _ = fs::remove_dir_all(&tmp);
}
