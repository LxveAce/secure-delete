//! Secure Delete CLI. The crypto-erase vault (the SSD solve) — for your own or authorized data only.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
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
    /// Create a new encrypted vault directory.
    Init { dir: PathBuf },
    /// Encrypt a file INTO the vault.
    Add { dir: PathBuf, file: PathBuf },
    /// List the files in the vault.
    List { dir: PathBuf },
    /// Extract a file out of the vault into a directory.
    Open { dir: PathBuf, id: String, out: PathBuf },
    /// Crypto-erase a file: destroy its key + re-key the vault (truly unrecoverable, even on SSD).
    Shred { dir: PathBuf, id: String },
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
}

const GIB: f64 = (1u64 << 30) as f64;

/// Read the vault passphrase. Prefers the `SECURE_DELETE_PASSPHRASE` env var; otherwise reads a line
/// from stdin. (A hidden terminal prompt is a follow-up — kept dependency-free for now.)
fn passphrase(_confirm: bool) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(p) = std::env::var("SECURE_DELETE_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(Zeroizing::new(p.into_bytes()));
        }
    }
    use std::io::Write;
    eprint!("Vault passphrase (SECURE_DELETE_PASSPHRASE to avoid the echo): ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).context("reading passphrase")?;
    let p = line.trim_end_matches(['\n', '\r']).to_string();
    if p.is_empty() {
        bail!("empty passphrase");
    }
    Ok(Zeroizing::new(p.into_bytes()))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Init { dir } => {
            Vault::new(&dir).init(&passphrase(true)?)?;
            println!("vault created at {}", dir.display());
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
    }
    Ok(())
}
