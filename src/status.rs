//! `status` — the honest per-volume advisor.
//!
//! It tells you the TRUTH about whether deleted data on a volume is actually protected: the media type,
//! whether the volume is full-disk-encrypted (the real SSD foundation), and whether TRIM is on — then it
//! advises. On an SSD, overwriting is futile; encryption is what protects deleted-file residue, so the
//! most useful thing the tool can do is point you at it.
use crate::detect::{probe, Media};
use std::path::Path;
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub struct Fde {
    pub backend: String,
    pub protection_on: bool,
    pub scope: String, // "full", "used-space-only", or "" if unknown
}

pub struct VolStatus {
    pub media: Media,
    pub filesystem: String,
    pub fde: Option<Fde>,
    pub trim: String,     // "enabled" / "disabled" / "unknown"
    pub advice: Vec<String>,
}

#[cfg(windows)]
fn drive_of(path: &Path) -> String {
    path.canonicalize()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .map(|s| {
            let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
            s.chars().take(2).collect::<String>() // "C:"
        })
        .unwrap_or_default()
}

#[cfg(windows)]
fn detect_fde(path: &Path) -> Option<Fde> {
    let drive = drive_of(path);
    if drive.len() < 2 {
        return None;
    }
    let out = run("manage-bde", &["-status", &drive]);
    if out.trim().is_empty() {
        return None; // manage-bde absent or needs elevation
    }
    let mut protection_on = false;
    let mut scope = String::new();
    let mut found = false;
    for line in out.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("Protection Status:") {
            found = true;
            protection_on = v.to_lowercase().contains("on");
        }
        if let Some(v) = l.strip_prefix("Conversion Status:") {
            found = true;
            let v = v.to_lowercase();
            if v.contains("used space") {
                scope = "used-space-only".into();
            } else if v.contains("fully") {
                scope = "full".into();
            }
        }
    }
    if !found {
        return None;
    }
    Some(Fde { backend: "BitLocker".into(), protection_on, scope })
}

#[cfg(windows)]
fn detect_trim() -> String {
    let out = run("fsutil", &["behavior", "query", "DisableDeleteNotify"]);
    let o = out.to_lowercase();
    // "NTFS DisableDeleteNotify = 0" -> TRIM enabled
    if o.contains("= 0") || o.contains("disabledeletenotify = 0") {
        "enabled".into()
    } else if o.contains("= 1") {
        "disabled".into()
    } else {
        "unknown".into()
    }
}

#[cfg(not(windows))]
fn detect_fde(path: &Path) -> Option<Fde> {
    let src = run("findmnt", &["-no", "SOURCE", "--target", &path.to_string_lossy()]);
    let src = src.trim();
    if src.is_empty() {
        return None;
    }
    let types = run("lsblk", &["-nso", "TYPE", src]); // device + parents' types
    if types.lines().any(|l| l.trim() == "crypt") {
        return Some(Fde { backend: "dm-crypt/LUKS".into(), protection_on: true, scope: "full".into() });
    }
    None
}

#[cfg(not(windows))]
fn detect_trim() -> String {
    "see `lsblk -D` / mount discard / fstrim".into()
}

pub fn status(path: &Path) -> VolStatus {
    let p = probe(path);
    let fde = detect_fde(path);
    let trim = detect_trim();
    let mut advice = vec![];

    match p.media {
        Media::Hdd => {
            advice.push("HDD: overwriting works here — `clean` and `overwrite` reliably destroy the bytes.".into());
        }
        Media::Ssd | Media::Unknown => {
            match &fde {
                Some(f) if f.protection_on && f.scope != "used-space-only" => {
                    advice.push("✓ Full-disk encryption is ON — deleted-file residue is ciphertext at rest (protected when the device is off/locked).".into());
                    advice.push("For quiet delete, keep TRIM enabled. For disposal, crypto-erase the volume key + run the drive's hardware Sanitize (NVMe/ATA).".into());
                    advice.push("Note: encryption does NOT protect a running, UNLOCKED system — for a per-file guarantee use the crypto-erase vault.".into());
                }
                Some(f) if f.protection_on && f.scope == "used-space-only" => {
                    advice.push("⚠ Encryption is 'Used-Space-Only' — old free space may still be plaintext. Switch to Full encryption, or crypto-erase the whole volume for disposal.".into());
                }
                Some(_) => {
                    advice.push("⚠ Encryption is present but Protection is OFF/suspended (a plaintext clear-key may be on the volume). Resume protection.".into());
                }
                None => {
                    advice.push("⚠ No full-disk encryption detected. On an SSD, overwriting CANNOT reliably reach deleted-file residue in the flash — enabling full-disk encryption (BitLocker / LUKS / FileVault) is the only reliable way to protect it.".into());
                }
            }
            if trim == "disabled" {
                advice.push("⚠ TRIM is disabled — deleted data lingers on the drive longer. Enable it (Windows: `fsutil behavior set DisableDeleteNotify 0`).".into());
            }
            advice.push("On SSD, `clean` issues TRIM (removes data from the host read path) rather than a wear-inducing overwrite. TRIM is not a physically-verifiable erase — the encryption above is what makes the residue safe.".into());
        }
    }

    VolStatus { media: p.media, filesystem: p.filesystem, fde, trim, advice }
}
