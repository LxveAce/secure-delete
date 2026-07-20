//! Secure Delete CLI. The crypto-erase vault (the SSD solve) — for your own or authorized data only.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use secure_delete::vault::{RootReport, TpmReport};
use secure_delete::Vault;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "secure-delete",
    about = "Honest secure deletion + a crypto-erase vault (destroy the key, not the bytes)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new encrypted vault directory (add --tpm to bind it to this machine's TPM).
    Init {
        dir: PathBuf,
        /// Bind the vault to this machine's TPM for a hardware-guaranteed shred (opt-in). You will get
        /// a one-time recovery code — a TPM clear / hardware change otherwise loses the vault.
        #[arg(long)]
        tpm: bool,
        /// With --tpm: skip the recovery kit. WARNING: a TPM clear or hardware change then makes the
        /// vault PERMANENTLY unrecoverable, even with the correct passphrase.
        #[arg(long)]
        i_understand_total_loss: bool,
    },
    /// Encrypt a file INTO the vault.
    Add { dir: PathBuf, file: PathBuf },
    /// List the files in the vault.
    List { dir: PathBuf },
    /// Extract a file out of the vault into a directory.
    Open { dir: PathBuf, id: String, out: PathBuf },
    /// Crypto-erase a file: destroy its key + re-key the vault (on SSD this is crypto-erase, not an overwrite).
    Shred { dir: PathBuf, id: String },
    /// Re-key the WHOLE vault under a new passphrase — a whole-vault crypto-erase of the software factor.
    Rekey { dir: PathBuf },
    /// (TPM vaults) Rotate the hardware key so any stale wrapped-master in flash can't be opened even with
    /// the passphrase. Optionally also crypto-erase a file. Crash-safe (persist-then-destroy).
    HardwareShred {
        dir: PathBuf,
        /// Also crypto-erase this entry id.
        id: Option<String>,
        /// Also drop the recovery kit — the strongest claim, but you then cannot recover without the TPM.
        #[arg(long)]
        destroy_recovery_kit: bool,
    },
    /// (TPM vaults) Reopen after TPM loss using the recovery code + passphrase: re-provision a hardware
    /// key on THIS machine, or (--to-software) convert to a passphrase-only vault.
    Recover {
        dir: PathBuf,
        /// Convert to a software vault instead of re-provisioning the TPM (drops the hardware guarantee).
        #[arg(long)]
        to_software: bool,
    },
    /// (TPM vaults) Retry destroying the old TPM key after an interrupted hardware-shred.
    RepairDestroy { dir: PathBuf },
    /// (read-only) Show a vault's root: software or TPM-backed, and whether the hardware key is reachable.
    VaultStatus { dir: PathBuf },
    /// Overwrite + delete a file in place (real on HDD; best-effort on SSD — use the vault for a guarantee).
    Overwrite {
        file: PathBuf,
        /// Actually erase (otherwise a dry-run).
        #[arg(long)]
        execute: bool,
        /// Confirmation: must equal the exact file path you gave.
        #[arg(long)]
        confirm: Option<String>,
    },
    /// (read-only) Show the detected media (HDD/SSD) + filesystem for a path.
    Detect { path: PathBuf },
    /// (read-only) Is deleted data on this volume actually protected? Reports media + encryption + TRIM, and advises.
    Status { path: PathBuf },
    /// Clean a volume's free space (overwrite unallocated space -> completes true deletion of already-removed files).
    Clean {
        dir: PathBuf,
        #[arg(long)]
        execute: bool,
        /// Cap how much fill to write, in GiB.
        #[arg(long)]
        max: Option<f64>,
        #[arg(long)]
        allow_system_volume: bool,
    },
    /// Live quietly: clean free space now, then again every `--interval` seconds (register via systemd / Task Scheduler).
    Service {
        dir: PathBuf,
        #[arg(long, default_value_t = 3600)]
        interval: u64,
        #[arg(long)]
        max: Option<f64>,
        #[arg(long)]
        allow_system_volume: bool,
    },
    /// One-click quiet mode: register the background `service` at logon + run one deep clean, then it lives quietly.
    Install {
        dir: PathBuf,
        #[arg(long, default_value_t = 21600)]
        interval: u64,
        #[arg(long)]
        allow_system_volume: bool,
        /// Cap the initial deep clean, in GiB.
        #[arg(long)]
        max: Option<f64>,
        /// Skip the one-time deep clean at install.
        #[arg(long)]
        no_initial_clean: bool,
        /// Show what would be registered/cleaned without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the quiet-mode scheduler entry (does NOT restore already-cleaned data — there's nothing to undo).
    Uninstall {
        dir: PathBuf,
        #[arg(long)]
        dry_run: bool,
    },
}

const GIB: f64 = (1u64 << 30) as f64;

/// Read a passphrase. Prefers the given env var; otherwise reads a line from stdin. (A hidden terminal
/// prompt is a follow-up — kept dependency-free for now.)
fn read_pass(env: &str, prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = std::env::var(env) {
        if !p.is_empty() {
            return Ok(Zeroizing::new(p.into_bytes()));
        }
    }
    use std::io::Write;
    eprint!("{prompt} (or set {env}): ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("reading passphrase")?;
    let p = line.trim_end_matches(['\n', '\r']).to_string();
    if p.is_empty() {
        bail!("empty passphrase");
    }
    Ok(Zeroizing::new(p.into_bytes()))
}

fn passphrase(_confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    read_pass("SECURE_DELETE_PASSPHRASE", "Vault passphrase")
}

/// Print the one-time recovery code (or the loud no-kit warning) after a TPM enrollment / rotation.
fn print_recovery(rep: &TpmReport) {
    match &rep.recovery_code {
        Some(code) => {
            println!();
            println!("  RECOVERY CODE — store this OFF this machine; it is shown only once:");
            println!("    {code}");
            println!("  It reopens the vault if this TPM is lost. Guard it like the data itself: anyone");
            println!("  with the code + this vault folder + the passphrase can open it.");
            println!();
        }
        None => {
            println!("  (no recovery kit — a TPM clear or hardware change will make this vault UNRECOVERABLE.)");
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Init { dir, tpm, i_understand_total_loss } => {
            if tpm {
                let rep = Vault::new(&dir).init_tpm(&passphrase(true)?, i_understand_total_loss)?;
                println!(
                    "hardware-rooted vault created at {} (provider: {}, key: {})",
                    dir.display(), rep.provider, rep.key_id
                );
                println!("It opens ONLY with this machine's TPM AND the passphrase.");
                print_recovery(&rep);
            } else {
                Vault::new(&dir).init(&passphrase(true)?)?;
                println!("vault created at {}", dir.display());
            }
        }
        Cmd::Add { dir, file } => {
            let id = Vault::new(&dir).add(&passphrase(false)?, &file)?;
            println!("added: {id}");
        }
        Cmd::List { dir } => {
            for (id, name, size) in Vault::new(&dir).list(&passphrase(false)?)? {
                println!("{id}  {size:>12}  {name}");
            }
        }
        Cmd::Open { dir, id, out } => {
            let p = Vault::new(&dir).open(&passphrase(false)?, &id, &out)?;
            println!("extracted: {}", p.display());
        }
        Cmd::Shred { dir, id } => {
            Vault::new(&dir).shred(&passphrase(false)?, &id)?;
            println!("shredded {id} + re-keyed the vault");
        }
        Cmd::Rekey { dir } => {
            let old = read_pass("SECURE_DELETE_PASSPHRASE", "Current passphrase")?;
            let new = read_pass("SECURE_DELETE_NEW_PASSPHRASE", "New passphrase")?;
            Vault::new(&dir).rekey(&old, &new)?;
            println!("re-keyed the vault under a new passphrase — old key material is now useless.");
        }
        Cmd::HardwareShred { dir, id, destroy_recovery_kit } => {
            let rep = Vault::new(&dir).hardware_shred(&passphrase(false)?, id.as_deref(), destroy_recovery_kit)?;
            match &id {
                Some(i) => println!("crypto-erased {i} and rotated the hardware key -> new key: {}", rep.key_id),
                None => println!("rotated the hardware key -> new key: {}", rep.key_id),
            }
            println!("any stale wrapped-master left in flash can no longer be opened, even with the passphrase.");
            print_recovery(&rep);
        }
        Cmd::Recover { dir, to_software } => {
            let code = read_pass("SECURE_DELETE_RECOVERY_CODE", "Recovery code")?;
            let code_s = String::from_utf8_lossy(&code).into_owned();
            let rep = Vault::new(&dir).recover(&code_s, &passphrase(false)?, to_software)?;
            if to_software {
                println!("converted to a software (passphrase-only) vault — the hardware guarantee no longer applies.");
            } else {
                println!("re-provisioned a hardware key on this machine -> key: {}", rep.key_id);
                print_recovery(&rep);
            }
        }
        Cmd::RepairDestroy { dir } => {
            if Vault::new(&dir).repair_destroy()? {
                println!("destroyed the leftover old TPM key from an interrupted hardware-shred.");
            } else {
                println!("nothing to repair — no interrupted hardware-shred found.");
            }
        }
        Cmd::VaultStatus { dir } => {
            match Vault::new(&dir).root_report()? {
                RootReport::Software => {
                    println!("root: passphrase (SOFTWARE-only)");
                    println!("  residual: a stale wrapped-master may linger in unaddressable SSD flash; recovering a");
                    println!("  shredded file would need that slot AND the passphrase. `rekey` closes it in software;");
                    println!("  a fresh `init --tpm` vault closes it in hardware.");
                }
                RootReport::Tpm { provider, key_id, scope, present, has_recovery, interrupted_shred } => {
                    println!("root: TPM+passphrase (provider={provider}, key={key_id}, scope={scope})");
                    match present {
                        Ok(true) => println!("  TPM: REACHABLE, key PRESENT — opens ONLY on this TPM + passphrase."),
                        Ok(false) => println!("  TPM present but this vault's key is GONE (hardware-shredded here, shredded on a sibling copy, or an interrupted rekey). Unopenable here — use `recover` with your recovery code."),
                        Err(e) => println!("  TPM UNREACHABLE: {e}. This hardware-bound vault cannot be opened here (moved machine, or TPM disabled). This is NOT a passphrase problem."),
                    }
                    println!("  recovery kit: {}", if has_recovery { "present (an off-device code can reopen after TPM loss)" } else { "NONE — a TPM clear or hardware change is permanent" });
                    if interrupted_shred {
                        println!("  WARNING: an interrupted hardware-shred was detected — the old TPM key may still exist. Run `repair-destroy`.");
                    }
                }
            }
        }
        Cmd::Overwrite { file, execute, confirm } => {
            let shown = file.to_string_lossy().to_string();
            if !execute {
                println!("PLAN (dry-run — nothing erased): overwrite + delete {shown}");
                println!("  note: real on HDD; BEST-EFFORT on SSD (use the vault for a guarantee).");
                println!("  to do it: --execute --confirm \"{shown}\"");
            } else {
                secure_delete::overwrite::secure_overwrite_file(&file, confirm.as_deref(), &shown)?;
                println!("overwritten + deleted: {shown}  (best-effort on SSD)");
            }
        }
        Cmd::Detect { path } => {
            let p = secure_delete::detect::probe(&path);
            println!("media: {}   filesystem: {}", p.media.as_str(), if p.filesystem.is_empty() { "(unknown)" } else { &p.filesystem });
        }
        Cmd::Status { path } => {
            let s = secure_delete::status::status(&path);
            println!("volume: {}", path.display());
            println!("  media:      {}", s.media.as_str());
            println!("  filesystem: {}", if s.filesystem.is_empty() { "(unknown)" } else { &s.filesystem });
            match &s.fde {
                Some(f) => println!(
                    "  encryption: {} — protection {}{}",
                    f.backend,
                    if f.protection_on { "ON" } else { "OFF" },
                    if f.scope.is_empty() { String::new() } else { format!(" ({})", f.scope) }
                ),
                None => println!("  encryption: none detected"),
            }
            println!("  trim:       {}", s.trim);
            println!("  advice:");
            for a in &s.advice {
                println!("    - {a}");
            }
        }
        Cmd::Clean { dir, execute, max, allow_system_volume } => {
            let media = secure_delete::detect::probe(&dir).media;
            let maxb = max.map(|g| (g * GIB) as u64);
            if !execute {
                println!("PLAN (dry-run): clean free space on {} [{}]", dir.display(), media.as_str());
                if media == secure_delete::detect::Media::Ssd {
                    println!("  SSD -> will issue TRIM (removes deleted data from the host read path; no overwrite, no wear).");
                    println!("  On SSD, full-disk encryption is what protects the residue — check `secure-delete status {}`.", dir.display());
                } else {
                    let (free, margin, budget) = secure_delete::freespace::plan(&dir, None, maxb)?;
                    println!(
                        "  {} -> overwrite-fill: free={} MiB, keep {} MiB margin, write ~{} MiB then delete it.",
                        media.as_str(), free >> 20, margin >> 20, budget >> 20
                    );
                    if secure_delete::freespace::is_system_volume(&dir) {
                        println!("  NOTE: this is the SYSTEM volume — add --allow-system-volume");
                    }
                }
                println!("  to run: --execute");
            } else {
                let msg = secure_delete::freespace::clean_volume(&dir, maxb, allow_system_volume)?;
                println!("cleaned: {msg}");
            }
        }
        Cmd::Service { dir, interval, max, allow_system_volume } => {
            let maxb = max.map(|g| (g * GIB) as u64);
            eprintln!("secure-delete: cleaning {} now, then every {interval}s (Ctrl-C to stop).", dir.display());
            loop {
                match secure_delete::freespace::clean_volume(&dir, maxb, allow_system_volume) {
                    Ok(msg) => eprintln!("[clean] {msg}"),
                    Err(e) => eprintln!("[clean] skipped: {e}"),
                }
                std::thread::sleep(std::time::Duration::from_secs(interval));
            }
        }
        Cmd::Install { dir, interval, allow_system_volume, max, no_initial_clean, dry_run } => {
            let maxb = max.map(|g| (g * GIB) as u64);
            let msg = secure_delete::install::install(&dir, interval, maxb, allow_system_volume, !no_initial_clean, dry_run)?;
            println!("{msg}");
        }
        Cmd::Uninstall { dir, dry_run } => {
            println!("{}", secure_delete::install::uninstall(&dir, dry_run)?);
        }
    }
    Ok(())
}
