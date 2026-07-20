//! Read-only media (HDD vs SSD) + filesystem detection, so the tool can pick the right SSD-aware strategy.
//! Shells out (no native FFI) to stay toolchain-light. Unknown -> the most conservative handling.
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media {
    Hdd,
    Ssd,
    Unknown,
}

impl Media {
    pub fn as_str(&self) -> &'static str {
        match self {
            Media::Hdd => "hdd",
            Media::Ssd => "ssd",
            Media::Unknown => "unknown",
        }
    }
}

pub struct Probe {
    pub media: Media,
    pub filesystem: String,
}

fn run(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

#[cfg(windows)]
pub fn probe(path: &Path) -> Probe {
    let p = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         $dl=(Get-Item -LiteralPath '{p}').PSDrive.Name; \
         $fs=(Get-Volume -DriveLetter $dl).FileSystemType; \
         $dn=(Get-Partition -DriveLetter $dl).DiskNumber; \
         $mt=(Get-Disk -Number $dn | Get-PhysicalDisk).MediaType; \
         Write-Output ('M='+$mt); Write-Output ('F='+$fs)"
    );
    let out = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &script]);
    let (mut m, mut fs) = (String::new(), String::new());
    for l in out.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("M=") {
            m = v.trim().to_string();
        }
        if let Some(v) = l.strip_prefix("F=") {
            fs = v.trim().to_string();
        }
    }
    let media = match m.to_uppercase().as_str() {
        "HDD" => Media::Hdd,
        "SSD" => Media::Ssd,
        _ => Media::Unknown,
    };
    Probe { media, filesystem: fs }
}

#[cfg(not(windows))]
pub fn probe(path: &Path) -> Probe {
    let target = path.to_string_lossy();
    let src = run("findmnt", &["-no", "SOURCE", "--target", &target]);
    let fs = run("findmnt", &["-no", "FSTYPE", "--target", &target]).trim().to_string();
    let src = src.trim();
    let rota = if src.is_empty() {
        String::new()
    } else {
        run("lsblk", &["-ndo", "ROTA", src])
    };
    let media = match rota.lines().next().map(str::trim) {
        Some("1") => Media::Hdd,
        Some("0") => Media::Ssd,
        _ => Media::Unknown,
    };
    Probe { media, filesystem: fs }
}
