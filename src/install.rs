//! One-click quiet mode: register the background free-space `service` to run at logon and (unless opted
//! out) run one initial deep clean — so the tool "lives quietly" after install. `uninstall` removes the
//! logon entry (it does NOT and cannot restore already-cleaned data — there is nothing to undo).
//!
//! Windows: a **per-user, no-admin** logon entry under `HKCU\...\Run`, launched through a generated
//! VBScript wrapper so the background clean runs with **no visible window**. All via `reg.exe` + a file
//! (no `windows-sys` dependency). Linux: the systemd unit + timer are generated and printed for you to
//! drop in and enable — honest + reversible, not auto-registered on an untested platform.
use crate::freespace;
#[cfg(windows)]
use anyhow::anyhow;
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A stable, per-directory entry name (so `uninstall` finds exactly what `install` made).
fn entry_name(dir: &Path) -> String {
    let mut h = Sha256::new();
    h.update(abs(dir).as_bytes());
    let d = h.finalize();
    format!("SecureDelete-Service-{:02x}{:02x}{:02x}{:02x}", d[0], d[1], d[2], d[3])
}

/// Absolute path as a clean string (strips Windows' `\\?\` verbatim prefix for display/args).
fn abs(dir: &Path) -> String {
    let p: PathBuf = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let s = p.to_string_lossy().into_owned();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

// --------------------------------------------------------------------------------------------------
#[cfg(windows)]
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// The app data dir path — computed WITHOUT creating it (so dry-runs and uninstall change nothing).
#[cfg(windows)]
fn app_dir_path() -> Result<PathBuf> {
    let base = std::env::var("LOCALAPPDATA").map_err(|_| anyhow!("LOCALAPPDATA is not set"))?;
    Ok(PathBuf::from(base).join("SecureDelete"))
}

#[cfg(windows)]
pub fn install(dir: &Path, interval: u64, max: Option<u64>, allow_system: bool, initial_clean: bool, dry_run: bool) -> Result<String> {
    use std::process::Command;
    let exe = std::env::current_exe()?.display().to_string();
    let name = entry_name(dir);
    let d = abs(dir);
    let sys = if allow_system { " --allow-system-volume" } else { "" };
    let human_cmd = format!("{exe} service \"{d}\" --interval {interval}{sys}");
    let app = app_dir_path()?;
    let vbs_path = app.join(format!("{name}.vbs"));

    // VBScript string literal: each embedded " is doubled. WScript.Shell.Run(..., 0, False) = hidden window.
    let cmd_literal = format!("\"\"\"{exe}\"\" service \"\"{d}\"\" --interval {interval}{sys}\"");
    let vbs = format!(
        "' Secure Delete quiet-mode launcher — runs the background free-space clean with no visible window.\r\nCreateObject(\"WScript.Shell\").Run {cmd_literal}, 0, False\r\n"
    );
    let run_val = format!("wscript.exe \"{}\"", vbs_path.display());

    if dry_run {
        return Ok(format!(
            "DRY-RUN (nothing changed):\n  launcher script: {}\n  logon entry: HKCU\\...\\Run['{name}']\n  runs at logon (hidden): {human_cmd}\n  initial deep clean: {}",
            vbs_path.display(),
            if initial_clean { "yes" } else { "no (--no-initial-clean)" }
        ));
    }

    std::fs::create_dir_all(&app)?;
    std::fs::write(&vbs_path, vbs)?;
    let out = Command::new("reg")
        .args(["add", RUN_KEY, "/v", &name, "/t", "REG_SZ", "/d", &run_val, "/f"])
        .output()?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&vbs_path);
        bail!("registering the logon entry failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }

    let mut msg = format!(
        "quiet mode installed — runs at your next logon, per-user, no admin, no window.\n  launcher: {}\n  logon entry: HKCU\\...\\Run['{name}']\n  (remove any time with `secure-delete uninstall \"{d}\"`)",
        vbs_path.display()
    );
    if initial_clean {
        match freespace::clean_volume(dir, max, allow_system) {
            Ok(r) => msg.push_str(&format!("\n  initial deep clean: {r}")),
            Err(e) => msg.push_str(&format!("\n  initial deep clean skipped: {e}")),
        }
    }
    Ok(msg)
}

#[cfg(windows)]
pub fn uninstall(dir: &Path, dry_run: bool) -> Result<String> {
    use std::process::Command;
    let name = entry_name(dir);
    let vbs_path = app_dir_path().ok().map(|d| d.join(format!("{name}.vbs")));
    if dry_run {
        return Ok(format!("DRY-RUN: would remove HKCU\\...\\Run['{name}'] + its launcher (already-cleaned data is not restorable)."));
    }
    let out = Command::new("reg").args(["delete", RUN_KEY, "/v", &name, "/f"]).output()?;
    if let Some(p) = &vbs_path {
        let _ = std::fs::remove_file(p);
    }
    if out.status.success() {
        return Ok(format!("quiet mode uninstalled — logon entry '{name}' + launcher removed. (Already-cleaned data is not restorable; nothing to undo.)"));
    }
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    if err.contains("unable to find") || err.contains("cannot find") {
        Ok(format!("no quiet-mode entry '{name}' was registered (already uninstalled)."))
    } else {
        bail!("removing the logon entry failed: {}", err.trim());
    }
}

// --------------------------------------------------------------------------------------------------
#[cfg(not(windows))]
pub fn install(dir: &Path, interval: u64, _max: Option<u64>, allow_system: bool, _initial_clean: bool, _dry_run: bool) -> Result<String> {
    let exe = std::env::current_exe()?.display().to_string();
    let d = abs(dir);
    let sys = if allow_system { " --allow-system-volume" } else { "" };
    let service = format!(
        "# ~/.config/systemd/user/secure-delete-clean.service\n[Unit]\nDescription=Secure Delete — quiet free-space clean\n\n[Service]\nType=oneshot\nExecStart={exe} clean \"{d}\" --execute{sys}\n"
    );
    let timer = format!(
        "# ~/.config/systemd/user/secure-delete-clean.timer\n[Unit]\nDescription=Run Secure Delete quiet clean periodically\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec={interval}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    );
    Ok(format!(
        "Linux quiet-mode setup (generated — drop these in and enable; not auto-registered on this platform):\n\n{service}\n{timer}\nThen:\n  systemctl --user daemon-reload\n  systemctl --user enable --now secure-delete-clean.timer"
    ))
}

#[cfg(not(windows))]
pub fn uninstall(_dir: &Path, _dry_run: bool) -> Result<String> {
    Ok("Linux: disable + remove the unit you installed:\n  systemctl --user disable --now secure-delete-clean.timer\n  rm ~/.config/systemd/user/secure-delete-clean.{service,timer}\n  systemctl --user daemon-reload".into())
}
