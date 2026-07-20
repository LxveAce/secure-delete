//! The crypto-erase vault: round-trip, wrong-passphrase rejection, and shred + re-key.
use secure_delete::Vault;
use std::fs;
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sdvault-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn add_open_roundtrip() {
    let tmp = scratch("rt");
    let src = tmp.join("secret.txt");
    fs::write(&src, b"top secret payload").unwrap();
    let v = Vault::new(tmp.join("vault"));
    v.init(b"correct horse").unwrap();
    let id = v.add(b"correct horse", &src).unwrap();
    let out = v.open(b"correct horse", &id, &tmp.join("out")).unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"top secret payload");
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn wrong_passphrase_fails() {
    let tmp = scratch("wp");
    let src = tmp.join("a.txt");
    fs::write(&src, b"data").unwrap();
    let v = Vault::new(tmp.join("vault"));
    v.init(b"right").unwrap();
    let id = v.add(b"right", &src).unwrap();
    assert!(v.open(b"wrong", &id, &tmp.join("out")).is_err());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn shred_removes_file_and_rekeys_survivors() {
    let tmp = scratch("sh");
    let f1 = tmp.join("one.txt");
    let f2 = tmp.join("two.txt");
    fs::write(&f1, b"one").unwrap();
    fs::write(&f2, b"two").unwrap();
    let v = Vault::new(tmp.join("vault"));
    v.init(b"pw").unwrap();
    let id1 = v.add(b"pw", &f1).unwrap();
    let id2 = v.add(b"pw", &f2).unwrap();

    v.shred(b"pw", &id1).unwrap();

    // the shredded file is gone (blob deleted + entry dropped)
    assert!(v.open(b"pw", &id1, &tmp.join("out")).is_err());
    // the survivor still opens after the vault re-key
    let out2 = v.open(b"pw", &id2, &tmp.join("out")).unwrap();
    assert_eq!(fs::read(&out2).unwrap(), b"two");
    // the shredded ciphertext blob is physically gone
    assert!(!tmp.join("vault").join("blobs").join(format!("{id1}.bin")).exists());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn overwrite_needs_confirmation_and_refuses_dirs() {
    let tmp = scratch("ow");
    let f = tmp.join("junk.txt");
    fs::write(&f, b"junk data").unwrap();
    let shown = f.to_string_lossy().to_string();
    // wrong / absent confirmation -> refuse; the file survives
    assert!(secure_delete::overwrite::secure_overwrite_file(&f, None, &shown).is_err());
    assert!(secure_delete::overwrite::secure_overwrite_file(&f, Some("nope"), &shown).is_err());
    assert!(f.exists());
    // a directory -> refuse
    let d = tmp.join("adir");
    fs::create_dir_all(&d).unwrap();
    let ds = d.to_string_lossy().to_string();
    assert!(secure_delete::overwrite::secure_overwrite_file(&d, Some(&ds), &ds).is_err());
    // correct confirmation -> erased
    secure_delete::overwrite::secure_overwrite_file(&f, Some(&shown), &shown).unwrap();
    assert!(!f.exists());
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn clean_free_space_capped_writes_and_cleans_up() {
    let tmp = scratch("clean");
    // small cap + allow_system (temp is on the system volume in dev/CI)
    let r = secure_delete::freespace::clean_free_space(&tmp, None, Some(4 * 1024 * 1024), true).unwrap();
    assert!(r.written_bytes <= 4 * 1024 * 1024); // never exceeds the cap
    assert!(!tmp.join(".secure-delete-clean-tmp").exists()); // fill removed
    let _ = fs::remove_dir_all(&tmp);
}
