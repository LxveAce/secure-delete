//! Best-effort overwrite-then-delete of a file (real on HDD; best-effort on SSD, honestly labeled).
use anyhow::{bail, Result};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Guard + confirm, then overwrite+delete a single file. `confirm` must equal `expected` (the exact
/// path the user gave) — a deliberate "type it again" gate. Refuses symlinks and non-regular files.
pub fn secure_overwrite_file(path: &Path, confirm: Option<&str>, expected: &str) -> Result<()> {
    let meta = fs::symlink_metadata(path)?; // does NOT follow symlinks
    if meta.file_type().is_symlink() {
        bail!("target is a symlink — refusing");
    }
    if !meta.is_file() {
        bail!("target is not a regular file — refusing");
    }
    if confirm != Some(expected) {
        bail!("confirmation required: re-run with --confirm \"{expected}\"");
    }
    best_effort_overwrite_delete(path)
}

/// Overwrite the file's bytes with random data, flush to disk, then remove it. Errors are non-fatal
/// for the overwrite step (we still unlink); the caller decides how strong a guarantee to claim.
pub fn best_effort_overwrite_delete(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_file() {
            if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
                let buf = crate::crypto::random_bytes::<4096>()?;
                let mut remaining = meta.len();
                f.seek(SeekFrom::Start(0))?;
                while remaining > 0 {
                    let n = remaining.min(buf.len() as u64) as usize;
                    f.write_all(&buf[..n])?;
                    remaining -= n as u64;
                }
                f.flush()?;
                let _ = f.sync_all();
            }
        }
    }
    let _ = fs::remove_file(path);
    Ok(())
}
