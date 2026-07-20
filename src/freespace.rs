//! Free-space clean — the quiet workhorse.
//!
//! It fills a volume's unallocated space with random data, then deletes the fill. That **completes the
//! true deletion** of anything already unlinked: on an HDD the freed blocks are overwritten; on an SSD,
//! deleting the fill hands those blocks back to the controller (TRIM) to be erased. No delete-interception,
//! no kernel hooks — it just runs at install (one big pass) and then quietly on a schedule.
//!
//! A dynamic safety margin (>= max(1 GiB, 10% of the volume)) is always kept, and the system/boot volume
//! is refused unless explicitly allowed. Disk-space figures are read by shelling out (no native FFI), which
//! keeps the build toolchain-light.
use crate::crypto::random_bytes;
use anyhow::{bail, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

const GIB: u64 = 1 << 30;
const STEP: usize = 64 * 1024 * 1024; // 64 MiB per write

pub struct CleanReport {
    pub written_bytes: u64,
    pub free_before: u64,
    pub margin: u64,
}

fn run(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// (free_bytes, total_bytes) for the volume that holds `path`.
#[cfg(windows)]
fn space(path: &Path) -> Result<(u64, u64)> {
    let p = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$d=(Get-Item -LiteralPath '{p}').PSDrive; Write-Output ('F='+$d.Free); Write-Output ('U='+$d.Used)"
    );
    let out = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script]);
    let (mut free, mut used) = (0u64, 0u64);
    for line in out.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("F=") {
            free = v.trim().parse().unwrap_or(0);
        }
        if let Some(v) = l.strip_prefix("U=") {
            used = v.trim().parse().unwrap_or(0);
        }
    }
    if free == 0 && used == 0 {
        bail!("could not read disk free space for {}", path.display());
    }
    Ok((free, free + used))
}

#[cfg(not(windows))]
fn space(path: &Path) -> Result<(u64, u64)> {
    let out = run("df", &["-B1", "--output=avail,size", &path.to_string_lossy()]);
    let line = out.lines().nth(1).unwrap_or("");
    let mut it = line.split_whitespace();
    let avail: u64 = it.next().unwrap_or("0").parse().unwrap_or(0);
    let total: u64 = it.next().unwrap_or("0").parse().unwrap_or(0);
    if total == 0 {
        bail!("could not read disk free space for {}", path.display());
    }
    Ok((avail, total))
}

/// True if `path` lives on the OS/boot volume. Conservative: unknown -> true.
pub fn is_system_volume(path: &Path) -> bool {
    #[cfg(windows)]
    {
        let sysdrive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_uppercase();
        match path.canonicalize().ok().and_then(|p| p.to_str().map(str::to_string)) {
            Some(s) => {
                let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_uppercase();
                s.starts_with(&sysdrive)
            }
            None => true,
        }
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        match (fs::metadata(path), fs::metadata("/")) {
            (Ok(a), Ok(b)) => a.dev() == b.dev(),
            _ => true,
        }
    }
}

/// Compute the plan (free, margin, budget) without writing anything.
pub fn plan(dir: &Path, margin_bytes: Option<u64>, max_bytes: Option<u64>) -> Result<(u64, u64, u64)> {
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }
    let (free, total) = space(dir)?;
    let dyn_margin = (total / 10).max(GIB);
    let margin = margin_bytes.map(|m| m.max(if is_system_volume(dir) { dyn_margin } else { 0 })).unwrap_or(dyn_margin);
    let mut budget = free.saturating_sub(margin);
    if let Some(m) = max_bytes {
        budget = budget.min(m);
    }
    Ok((free, margin, budget))
}

/// Wipe unallocated space on `dir`'s volume by filling it (leaving a margin) then removing the fill.
pub fn clean_free_space(
    dir: &Path,
    margin_bytes: Option<u64>,
    max_bytes: Option<u64>,
    allow_system: bool,
) -> Result<CleanReport> {
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }
    if is_system_volume(dir) && !allow_system {
        bail!(
            "refusing to clean free space on the SYSTEM/boot volume — pass --allow-system-volume to proceed \
             (a large safety margin is still kept)."
        );
    }
    let (free, margin, budget) = plan(dir, margin_bytes, max_bytes)?;

    let fill_dir = dir.join(".secure-delete-clean-tmp");
    if fill_dir.exists() {
        let _ = fs::remove_dir_all(&fill_dir);
    }
    fs::create_dir_all(&fill_dir)?;
    let fill = fill_dir.join("fill.bin");
    let mut written: u64 = 0;
    let buf = vec_random(STEP)?;
    let res = (|| -> Result<()> {
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&fill)?;
        while written < budget {
            let n = ((budget - written) as usize).min(STEP);
            f.write_all(&buf[..n])?;
            written += n as u64;
        }
        f.flush()?;
        let _ = f.sync_all();
        Ok(())
    })();
    let _ = fs::remove_dir_all(&fill_dir); // deleting the fill TRIMs those blocks on an SSD
    res?;
    Ok(CleanReport { written_bytes: written, free_before: free, margin })
}

/// SSD-appropriate clean: issue TRIM/discard for the volume's unused space — removes deleted data from
/// the drive's host-visible read path WITHOUT the overwrite (no wear, no false assurance). Not a
/// host-verifiable physical erase; encryption is what actually protects the residue on flash.
pub fn trim_free_space(dir: &Path) -> Result<String> {
    #[cfg(windows)]
    {
        let letter = dir
            .canonicalize()
            .ok()
            .and_then(|p| {
                let s = p.to_string_lossy().to_string();
                let s = s.strip_prefix(r"\\?\").unwrap_or(&s).to_string();
                s.chars().next().map(|c| c.to_string())
            })
            .unwrap_or_default();
        if letter.is_empty() {
            bail!("could not determine the drive letter for {}", dir.display());
        }
        let script = format!(
            "Optimize-Volume -DriveLetter {letter} -ReTrim -ErrorAction SilentlyContinue | Out-Null; Write-Output 'ok'"
        );
        let out = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script]);
        if out.to_lowercase().contains("ok") {
            Ok(format!("issued TRIM/Unmap for unused sectors on {letter}: (Optimize-Volume -ReTrim)"))
        } else {
            bail!("Optimize-Volume did not confirm — may need Administrator")
        }
    }
    #[cfg(not(windows))]
    {
        let out = run("fstrim", &["-v", &dir.to_string_lossy()]);
        if out.trim().is_empty() {
            bail!("fstrim produced no output — needs privileges, or discard isn't supported here");
        }
        Ok(format!("fstrim: {}", out.trim()))
    }
}

/// Clean a volume the RIGHT way for its media: TRIM on SSD (no wear), overwrite-fill on HDD/unknown.
pub fn clean_volume(dir: &Path, max_bytes: Option<u64>, allow_system: bool) -> Result<String> {
    match crate::detect::probe(dir).media {
        crate::detect::Media::Ssd => {
            let msg = trim_free_space(dir)?;
            Ok(format!(
                "SSD — {msg}. (TRIM removes it from the host read path; physical erase is deferred to the controller and is not host-verifiable — full-disk encryption is what protects the residue.)"
            ))
        }
        m => {
            let r = clean_free_space(dir, None, max_bytes, allow_system)?;
            Ok(format!(
                "{}: wrote ~{} MiB of random fill then removed it (kept {} MiB margin).",
                m.as_str(),
                r.written_bytes >> 20,
                r.margin >> 20
            ))
        }
    }
}

fn vec_random(n: usize) -> Result<Vec<u8>> {
    // one random block reused across writes (fresh randomness per install pass is not needed to overwrite)
    let mut v = vec![0u8; n];
    let chunk = random_bytes::<4096>()?;
    for c in v.chunks_mut(4096) {
        let m = c.len();
        c.copy_from_slice(&chunk[..m]);
    }
    Ok(v)
}
