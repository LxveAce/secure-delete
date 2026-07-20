//! `sanitize` — how to wipe a WHOLE drive for disposal. This never runs anything. The real erase is the
//! drive's own hardware Sanitize or Secure Erase, which you run yourself after reading the caveats. For a
//! disused SSD that's the NIST-grade wipe; an overwrite isn't. The command works out your device and
//! interface and prints the right command for it.
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Interface {
    Nvme,
    Ata,
    Unknown,
}

impl Interface {
    pub fn as_str(&self) -> &'static str {
        match self {
            Interface::Nvme => "NVMe",
            Interface::Ata => "ATA/SATA",
            Interface::Unknown => "unknown",
        }
    }
}

pub struct Advice {
    pub device: String,
    pub interface: Interface,
    pub commands: Vec<String>,
    pub notes: Vec<String>,
}

fn run(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// The exact commands for a Unix host, given the interface. Pure, so it's unit-tested directly.
fn unix_commands(iface: &Interface, dev: &str) -> (Vec<String>, Vec<String>) {
    let mut cmds = vec![];
    let mut notes = vec![format!("This wipes the ENTIRE device {dev}, not one file. Back up anything you need first.")];
    match iface {
        Interface::Nvme => {
            cmds.push(format!("sudo nvme id-ctrl {dev}                 # confirm Sanitize support (SANICAP)"));
            cmds.push(format!("sudo nvme sanitize -a 2 {dev}           # block erase (use -a 4 for crypto erase if supported)"));
            cmds.push(format!("sudo nvme sanitize-log {dev}            # watch it finish"));
        }
        Interface::Ata => {
            notes.push("ATA Secure Erase only runs when the drive is not \"frozen\". If `hdparm -I` says frozen, suspend and resume the machine, or hot-replug the drive, to clear it.".into());
            cmds.push(format!("sudo hdparm -I {dev}                    # confirm \"supported: enhanced erase\" and \"not frozen\""));
            cmds.push(format!("sudo hdparm --user-master u --security-set-pass p {dev}"));
            cmds.push(format!("sudo hdparm --user-master u --security-erase p {dev}   # the wipe"));
        }
        Interface::Unknown => {
            notes.push("Couldn't tell whether this is NVMe or ATA. Check `lsblk -o NAME,TRAN`, then use `nvme` for NVMe or `hdparm` for SATA.".into());
        }
    }
    notes.push("For an SSD this hardware erase is the disposal-grade wipe (NIST SP 800-88 Purge). An overwrite isn't.".into());
    (cmds, notes)
}

#[cfg(not(windows))]
fn detect(path: &Path) -> (String, Interface) {
    let src = run("findmnt", &["-no", "SOURCE", "--target", &path.to_string_lossy()]);
    let src = src.trim();
    if src.is_empty() {
        return ("(unknown)".into(), Interface::Unknown);
    }
    // Parent whole-disk device (e.g. /dev/nvme0n1p2 -> nvme0n1, /dev/sda2 -> sda).
    let pk = run("lsblk", &["-no", "PKNAME", src]);
    let dev = pk
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|n| format!("/dev/{n}"))
        .unwrap_or_else(|| src.to_string());
    let tran = run("lsblk", &["-ndo", "TRAN", &dev]).to_lowercase();
    let iface = if dev.contains("nvme") || tran.contains("nvme") {
        Interface::Nvme
    } else if tran.contains("sata") || tran.contains("ata") || dev.contains("/sd") {
        Interface::Ata
    } else {
        Interface::Unknown
    };
    (dev, iface)
}

#[cfg(not(windows))]
pub fn advise(path: &Path) -> Advice {
    let (device, interface) = detect(path);
    let (commands, mut notes) = unix_commands(&interface, &device);
    notes.push("This command runs nothing. Review the steps and run them yourself.".into());
    Advice { device, interface, commands, notes }
}

// --------------------------------------------------------------------------------------------------
#[cfg(windows)]
fn drive_of(path: &Path) -> String {
    path.canonicalize()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .map(|s| s.strip_prefix(r"\\?\").unwrap_or(&s).chars().take(2).collect::<String>())
        .unwrap_or_default()
}

#[cfg(windows)]
pub fn advise(path: &Path) -> Advice {
    let drive = drive_of(path);
    let letter = drive.trim_end_matches(':');
    // Disk number + bus type (NVMe / SATA) for the volume.
    let ps = format!(
        "$p=Get-Partition -DriveLetter {letter} -ErrorAction SilentlyContinue; if($p){{$d=Get-Disk -Number $p.DiskNumber; Write-Output \"$($d.Number)|$($d.BusType)\"}}"
    );
    let out = run("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps]);
    let (disk_no, bus) = out
        .lines()
        .find(|l| l.contains('|'))
        .and_then(|l| l.split_once('|'))
        .map(|(a, b)| (a.trim().to_string(), b.trim().to_lowercase()))
        .unwrap_or_default();
    let interface = if bus.contains("nvme") {
        Interface::Nvme
    } else if bus.contains("sata") || bus.contains("ata") {
        Interface::Ata
    } else {
        Interface::Unknown
    };
    let device = if disk_no.is_empty() {
        format!("the disk behind {drive}")
    } else {
        format!("PhysicalDrive{disk_no} ({}, behind {drive})", interface.as_str())
    };

    let bitlocker = run("manage-bde", &["-status", &drive]).to_lowercase().contains("protection on");

    let mut notes = vec!["Windows has no built-in whole-drive Sanitize command.".to_string()];
    if bitlocker {
        notes.push("This drive is BitLocker-encrypted, so its contents are already ciphertext. Reformatting it and removing the key effectively wipes the whole drive in one step.".into());
    }
    notes.push("For a real hardware erase, use the drive maker's secure-erase tool (Samsung Magician, WD Dashboard, and so on), or boot a Linux USB and run the commands below.".into());

    // The Linux commands you'd run from a USB stick; the device name there is a placeholder.
    let placeholder = if interface == Interface::Nvme { "/dev/nvme0n1" } else { "/dev/sdX" };
    let (commands, mut more) = unix_commands(&interface, placeholder);
    more.push("This command runs nothing. Review the steps and run them yourself.".into());
    notes.extend(more);

    Advice { device, interface, commands, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_commands_use_nvme_sanitize() {
        let (cmds, _notes) = unix_commands(&Interface::Nvme, "/dev/nvme0n1");
        assert!(cmds.iter().any(|c| c.contains("nvme sanitize -a 2 /dev/nvme0n1")));
        assert!(cmds.iter().any(|c| c.contains("nvme sanitize-log")));
    }

    #[test]
    fn ata_commands_use_hdparm_and_warn_about_frozen() {
        let (cmds, notes) = unix_commands(&Interface::Ata, "/dev/sda");
        assert!(cmds.iter().any(|c| c.contains("hdparm --user-master u --security-erase p /dev/sda")));
        assert!(notes.iter().any(|n| n.to_lowercase().contains("frozen")));
    }

    #[test]
    fn unknown_interface_gives_no_commands_but_explains() {
        let (cmds, notes) = unix_commands(&Interface::Unknown, "/dev/foo");
        assert!(cmds.is_empty());
        assert!(notes.iter().any(|n| n.contains("NVMe or ATA")));
    }
}
