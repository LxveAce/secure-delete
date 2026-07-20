//! One-click quiet mode: register the background free-space `service` to run in the background and
//! (unless opted out) run one initial deep clean, so the tool keeps working after install. `uninstall`
//! removes the registration. It can't bring back already-cleaned data, so there's nothing to undo there.
//!
//! Windows uses a per-user, no-admin entry under `HKCU\...\Run`, started through a generated VBScript
//! wrapper so the clean runs with no visible window, all via `reg.exe` and a file (no `windows-sys`).
//! Linux writes a systemd user service + timer and enables the timer. If there's no systemd user session
//! (a headless box, for instance), it writes the units anyway and prints the two commands to finish by hand.
use crate::freespace;
use anyhow::anyhow;
#[cfg(windows)]
use anyhow::bail;
use anyhow::Result;
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A stable, per-directory entry name (so `uninstall` finds exactly what `install` made).
#[cfg(windows)]
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
fn systemd_units(dir: &Path, interval: u64, allow_system: bool) -> Result<(String, String)> {
    let exe = std::env::current_exe()?.display().to_string();
    let d = abs(dir);
    let sys = if allow_system { " --allow-system-volume" } else { "" };
    let service = format!(
        "[Unit]\nDescription=Secure Delete quiet free-space clean\n\n[Service]\nType=oneshot\nExecStart={exe} clean \"{d}\" --execute{sys}\n"
    );
    let timer = format!(
        "[Unit]\nDescription=Run Secure Delete quiet clean on a schedule\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec={interval}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
    );
    Ok((service, timer))
}

#[cfg(not(windows))]
fn user_unit_dir() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map_err(|_| anyhow!("neither XDG_CONFIG_HOME nor HOME is set"))?;
    Ok(base.join("systemd").join("user"))
}

/// Best-effort `systemctl --user`; returns whether it succeeded (false if there's no user session).
#[cfg(not(windows))]
fn systemctl(args: &[&str]) -> bool {
    std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
pub fn install(dir: &Path, interval: u64, max: Option<u64>, allow_system: bool, initial_clean: bool, dry_run: bool) -> Result<String> {
    let (service, timer) = systemd_units(dir, interval, allow_system)?;
    let unit_dir = user_unit_dir()?;
    if dry_run {
        return Ok(format!(
            "DRY-RUN (nothing changed):\n  would write {}/secure-delete-clean.{{service,timer}}\n  then: systemctl --user daemon-reload && systemctl --user enable --now secure-delete-clean.timer\n  initial deep clean: {}",
            unit_dir.display(),
            if initial_clean { "yes" } else { "no (--no-initial-clean)" }
        ));
    }

    std::fs::create_dir_all(&unit_dir)?;
    std::fs::write(unit_dir.join("secure-delete-clean.service"), &service)?;
    std::fs::write(unit_dir.join("secure-delete-clean.timer"), &timer)?;

    let enabled = systemctl(&["daemon-reload"]) && systemctl(&["enable", "--now", "secure-delete-clean.timer"]);
    let mut msg = format!("wrote the systemd user units to {}", unit_dir.display());
    if enabled {
        msg.push_str("\nenabled secure-delete-clean.timer; it cleans on a schedule now.");
    } else {
        msg.push_str("\ncouldn't enable it here (no systemd user session). Finish with:\n  systemctl --user daemon-reload\n  systemctl --user enable --now secure-delete-clean.timer");
    }
    if initial_clean {
        match freespace::clean_volume(dir, max, allow_system) {
            Ok(r) => msg.push_str(&format!("\ninitial deep clean: {r}")),
            Err(e) => msg.push_str(&format!("\ninitial deep clean skipped: {e}")),
        }
    }
    Ok(msg)
}

#[cfg(not(windows))]
pub fn uninstall(_dir: &Path, dry_run: bool) -> Result<String> {
    let unit_dir = user_unit_dir()?;
    if dry_run {
        return Ok(format!(
            "DRY-RUN: would disable the timer and remove {}/secure-delete-clean.{{service,timer}}",
            unit_dir.display()
        ));
    }
    let _ = systemctl(&["disable", "--now", "secure-delete-clean.timer"]);
    let removed_svc = std::fs::remove_file(unit_dir.join("secure-delete-clean.service")).is_ok();
    let removed_tim = std::fs::remove_file(unit_dir.join("secure-delete-clean.timer")).is_ok();
    let _ = systemctl(&["daemon-reload"]);
    if removed_svc || removed_tim {
        Ok("removed the systemd user units and disabled the timer. (Already-cleaned data can't be brought back.)".into())
    } else {
        Ok("no secure-delete units were installed (already uninstalled).".into())
    }
}
