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
}

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
    }
    Ok(())
}
