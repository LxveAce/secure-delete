# Secure Delete

When you delete a file, the data doesn't actually go away. Secure Delete gets rid of it for real. On the drives where "for real" isn't possible, it tells you so instead of pretending.

[![License: MIT](https://img.shields.io/github/license/LxveAce/secure-delete)](LICENSE)
[![Stars](https://img.shields.io/github/stars/LxveAce/secure-delete?style=social)](https://github.com/LxveAce/secure-delete/stargazers)

[Cyber Controller](https://cybercontroller.org) · [LxveLabs](https://lxvelabs.com) · [Discord](https://discord.gg/lxvelabs)

A secure-deletion tool from LxveAce / LxveLabs, in the same family as `shred`, `sdelete`, BleachBit, and VeraCrypt. For data you own or are cleared to wipe. The one rule it holds itself to: never claim more than the drive can actually deliver.

> [!WARNING]
> This permanently erases data. It defaults to safe: `overwrite` does nothing without `--execute` and a matching `--confirm`, and it refuses symlinks and directories. Keys stay in zeroized memory and never touch the disk in the clear. Use it on your own data. See [SAFETY.md](SAFETY.md).

## "Delete" doesn't delete

Deleting a file, or emptying the trash, only unlinks it. The OS forgets where the file lives and marks the space free, but the bytes sit on the disk until something else happens to write over them. That's why recovery tools pull "deleted" files off drives every day. A 2025 survey of second-hand drives found about 42% still carried recoverable personal data: bank details, IDs, documents the seller assumed were long gone.

## Overwriting isn't enough on an SSD

On a spinning hard drive, overwriting a file's bytes really does destroy them. One pass is enough; the old 7-pass and 35-pass rituals are myths on modern hardware.

SSDs are where it breaks down. The controller writes your "overwrite" to a fresh cell and leaves the original sitting in flash the OS can't even address. A well-known UC San Diego study recovered anywhere from 4% to 75% of data after a full-drive overwrite attempt. So on an SSD, overwriting one file is best-effort at best, and any tool that calls the result "unrecoverable" is lying to you.

## What it does

Two modes.

**Quiet mode** is the default. You install it once, it runs one deep free-space clean, and then it sits in the background and cleans free space on a schedule. Anything you delete the normal way gets its leftover data overwritten (on an HDD) or handed back to the drive with TRIM (on an SSD) a little later, with no effort from you. No delete hooks, no kernel driver. It just runs.

**Vault mode** is for the files you want a real guarantee on. Each one is encrypted with its own key as it goes in. To shred it, the tool destroys the key and re-keys the vault, so the ciphertext left behind in flash is just noise. That's cryptographic erase (NIST SP 800-88r2), the same thing that wipes an iPhone in seconds. A software vault leaves one small gap: an old wrapped key could linger in unaddressable flash, and someone could recover a shredded file only if they had that exact NAND slot *and* your passphrase. Bind the vault to your TPM with `init --tpm` and even that gap closes. Destroy the TPM key and a shredded file can't be opened again, not even by someone holding a full image of the flash and the passphrase.

## What it can and can't guarantee

The tool never prints a bare "unrecoverable." What you actually get depends on the drive:

- **HDD.** Overwrite works. One pass and that file's blocks are gone.
- **SSD.** Overwriting can't reliably reach the flash, and it wears the drive for nothing, so quiet mode issues TRIM instead. TRIM drops the data from the drive's host-visible read path, but the physical erase happens whenever the controller gets around to it, so it isn't a verified wipe. The thing that actually protects deleted data on an SSD is full-disk encryption, because then the leftover bytes are already ciphertext. Run `secure-delete status` and it tells you whether your drive is encrypted and TRIM is on, and what to turn on if not.
- **Vault (crypto-erase).** A per-file guarantee that holds even on an SSD, with two conditions: the data went in encrypted (nothing plaintext to recover), and the key never leaked (no copy paged out to swap or hibernation). A software vault leaves the small gap above; a TPM vault closes it. On Windows the TPM key is a wrapped blob kept on disk that only this machine's TPM can use, so deleting it is strong, but it's defense in depth rather than a wipe inside the chip. On Linux the key stays inside the TPM itself and gets evicted, which is a true in-hardware erase.
- **Whole drive.** For disposal, the drive's own hardware secure-erase (NVMe or ATA Sanitize) is the real wipe. Run `secure-delete sanitize <path>` and it works out your drive and interface and prints the exact command, with the caveats. It runs nothing itself; you run the command after reading it.

## Coverage by drive type

| Storage / FS | File overwrite | What we'll claim | What to use instead |
|---|---|---|---|
| HDD, in-place FS | reliable, 1 pass | "current blocks overwritten; recovery infeasible" | overwrite + free-space wipe |
| SSD / NVMe / flash | unreliable | never "unrecoverable" | crypto-erase; hardware Sanitize to dispose |
| CoW / snapshot FS (btrfs, ZFS, APFS, ReFS) | old blocks pinned by snapshots | "current blocks only" | crypto-erase; delete snapshots first |
| NTFS resident / compressed / sparse | reallocated on write | (handled) | SDelete-style cluster overwrite + free-MFT fill |

Default is one pass. Multi-pass Gutmann and DoD schemes are obsolete on modern drives; NIST says so, and so does Gutmann. A file wipe also can't reach a handful of side channels, so instead of glossing over them the tool tells you they exist: VSS shadow copies, the pagefile and hiberfil, temp files and thumbnail caches, `$LogFile` and `$UsnJrnl`, filenames left in directory slack, and the SSD's spare and over-provisioned area.

## What works today

- **`status`** looks at a volume and tells you whether deleted data there is actually safe: HDD or SSD, whether it's encrypted and how much of it, and whether TRIM is on. On an unencrypted SSD it tells you to turn on full-disk encryption, because overwriting won't save you there. `detect` gives you just the media type and filesystem.
- **Quiet clean.** `clean` overwrites free space on an HDD and issues TRIM on an SSD. `service` keeps it running on a schedule, and `install` sets the whole thing up in one command (on Windows: per-user, no admin, no visible window).
- **The vault** — `init`, `add`, `list`, `open`, `shred`, `rekey`. Shred destroys a file's key and re-keys the vault. `rekey` changes the passphrase and re-keys everything, which is the software way to kill any stale key material an SSD left behind.
- **TPM-backed vault.** `init --tpm` ties the vault to this machine's TPM, so opening it needs both the hardware and the passphrase. `hardware-shred` rotates the TPM key, which kills any stale wrapped key in flash for good. If the TPM ever dies you reopen with a one-time recovery code (`recover`), and `vault-status` tells you whether the hardware key is still there. Works on Windows (Platform Crypto Provider, no admin) and Linux (tpm2-tools, verified in CI against an emulated TPM). macOS Secure Enclave is designed but not built yet.
- **`overwrite`** wipes a single file in place, real on an HDD and best-effort on an SSD, behind a confirmation gate.
- **`sanitize`** is the disposal helper: it detects the drive behind a path and prints its hardware secure-erase command (`nvme sanitize` or the `hdparm` sequence), with caveats. Advisory, runs nothing.
- Written in Rust. Keys are held in zeroized buffers, the crypto is RustCrypto (AES-256-GCM, Argon2id, HKDF), and it builds to one self-contained binary.

The original v0.1 (Python, tagged [`v0.1.0`](https://github.com/LxveAce/secure-delete/tree/v0.1.0)) still holds the media/filesystem detection and the advisory whole-drive sanitize command, which are being ported over.

## Try it
```
cargo build --release

# is your drive actually protected?
secure-delete status ./folder
secure-delete detect ./folder

# getting rid of the whole drive? print its hardware erase command
secure-delete sanitize ./folder

# quiet mode: overwrite on HDD, TRIM on SSD
secure-delete clean   ./folder                         # dry-run: shows the plan, writes nothing
secure-delete clean   ./folder --execute               # do it (add --allow-system-volume for C:/ or /)
secure-delete service ./folder --interval 3600         # clean now, then hourly

# vault mode: crypto-erase, even on SSD
export SECURE_DELETE_PASSPHRASE="your passphrase"
secure-delete init  ./myvault                          # software vault
secure-delete init  ./myvault --tpm                    # or bind it to this machine's TPM (prints a recovery code)
secure-delete add   ./myvault ./secret.pdf             # encrypted the moment it goes in
secure-delete shred ./myvault <id>                     # destroy the key and re-key the vault
secure-delete hardware-shred ./myvault                 # TPM vaults: rotate the hardware key
secure-delete vault-status ./myvault                   # is the hardware key still reachable?
SECURE_DELETE_NEW_PASSPHRASE="new" secure-delete rekey ./myvault   # change the passphrase, re-key everything

cargo test
```

## Run it in the background
The idea behind quiet mode is that you set it up once and forget about it. `install` runs one deep clean and then registers the background cleaner to start at login.
```
secure-delete install C:\ --allow-system-volume     # Windows: per-user, no admin, no window; cleans once now
secure-delete install /home --interval 21600        # pick the volume and how often (seconds)
secure-delete install C:\ --dry-run                 # show what it would register, change nothing
secure-delete uninstall C:\                          # stop it (already-cleaned data can't be brought back)
```
On Windows this adds a per-user login entry under `HKCU\…\Run` that starts the background `service` with no visible window and no admin. On Linux it writes a systemd user service and timer and enables the timer. On a headless box with no user session it still writes the units and prints the two commands to finish by hand.

## Roadmap
- **v0.1 (Python)** — per-file overwrite, guards, media/FS detection, free-space wipe, advisory sanitize. Tagged `v0.1.0`.
- **v0.2 (Rust)** — the `status` advisor, media-aware quiet clean (overwrite on HDD, TRIM on SSD), the crypto-erase vault (`init`/`add`/`list`/`open`/`shred`), per-file overwrite.
- **v0.2.3** — whole-vault `rekey` (a passphrase change re-keys everything), the software way to close the SSD residue.
- **v0.3.0** — an opt-in TPM-backed vault root (`init --tpm`) and `hardware-shred` that closes the SSD residue in hardware, a one-time recovery kit with `recover`, and `vault-status`. Windows complete; Linux and macOS roots designed.
- **v0.3.1** — one-command `install`/`uninstall` for quiet mode. On Windows a per-user, no-admin, hidden login entry that runs the background clean; on Linux a generated systemd unit and timer.
- **v0.3.2 (current)** — the Linux tpm2-tools hardware root. The key is sealed into a persisted, evictable TPM object, so `hardware-shred` evicting it is a true in-hardware erase, stronger than the on-disk key blob Windows uses. Verified in CI against an emulated TPM.
- **v0.3.3** — Linux `install` now writes and enables the systemd user service and timer itself, instead of just printing them, matching the one-command setup Windows already had.
- **v0.3.4 (current)** — a `sanitize` command that detects your drive and interface and prints the exact hardware secure-erase command for disposal. Advisory, runs nothing.
- **Next** — the macOS Secure Enclave root (needs a signed Swift helper and Apple hardware), fscrypt as a "protected folder", and a desktop GUI.

Design notes and rationale are in [PLAN.md](PLAN.md). Safety posture is in [SAFETY.md](SAFETY.md).

## Ground rules
Your own data only. Safe by default. Claims scoped to what the drive can do. No telemetry, works offline.

---
Built by LxveAce, part of [LxveLabs](https://lxvelabs.com). Questions or ideas: [Discord](https://discord.gg/lxvelabs), or open an issue.
