# Secure Delete

> **When you delete a file, it's not actually gone.** Secure Delete makes it gone — honestly, and even on an SSD.

[![License: MIT](https://img.shields.io/github/license/LxveAce/secure-delete)](LICENSE)
[![Stars](https://img.shields.io/github/stars/LxveAce/secure-delete?style=social)](https://github.com/LxveAce/secure-delete/stargazers)

**[Cyber Controller](https://cybercontroller.org)** · **[LxveLabs](https://lxvelabs.com)** · **[Discord](https://discord.gg/lxvelabs)**

A secure-deletion tool from **LxveAce / LxveLabs** — for your own or authorized data only. Same lineage as `shred` /
`sdelete` / BleachBit / VeraCrypt, built on one honest idea: **make the data truly gone, and never claim more than the
hardware can actually deliver.**

> [!WARNING]
> **This tool permanently erases data** — but it's built to be careful. The **crypto-erase vault** and per-file
> **overwrite** are real; `overwrite` is a dry-run unless you pass `--execute` + `--confirm`, and refuses symlinks and
> non-files. Keys live in zeroized memory and never touch disk in the clear. **For your own or authorized data only.**
> See [SAFETY.md](SAFETY.md).

## The problem: "delete" doesn't delete
Deleting a file — or emptying the trash — only **unlinks** it. The OS forgets where the file is and marks the space
"free," but the **actual bytes stay on the disk** until something else happens to write over them. That's why "deleted"
files are recovered every day with off-the-shelf forensic tools. A 2025 study of second-hand drives found **~42% still
held recoverable personal data** — bank details, IDs, documents the previous owner thought were gone. Emptying the trash
erases nothing.

## Why "just overwrite it" isn't enough (especially on an SSD)
On a **hard drive**, overwriting the file's bytes really does destroy them — one pass is plenty (the old "7-pass /
35-pass" advice is myth on modern drives). But most machines run **SSDs**, and an SSD quietly works against you: its
controller writes your "overwrite" to a *different* physical cell and leaves the original sitting in flash the OS **can't
even address**. A landmark UC San Diego study recovered **4–75% of data after a full-drive overwrite attempt**. So on an
SSD, overwriting a file is best-effort at best — and any tool that calls it "unrecoverable" is lying to you.

## Our answer: make it gone, quietly
Two modes, so "delete" finally means delete:

**1 — Quiet mode (the default).** Install it, let it run one deep **free-space clean**, then it lives quietly and cleans
free space on a schedule. Whatever you delete the normal way gets its leftover data **overwritten** (on an HDD) and handed
back to the drive to erase via **TRIM** (on an SSD) shortly after — with zero effort from you. Simple by design: no
delete-hooks, no kernel drivers, it just runs.

**2 — Vault mode (a hardware-independent guarantee, even on SSD).** For data you want a hard promise on, put it in the
**crypto-erase vault**: each file is encrypted with its own key on the way in; to shred it, the key is destroyed and the
vault re-keyed, so the ciphertext on the flash becomes permanent noise. This is **cryptographic erase** (NIST SP 800-88r2)
— the same trick that wipes an iPhone in seconds.

## What we promise — and what we don't (honesty first)
Secure Delete **never prints a bare "unrecoverable."** Every claim is scoped to what actually happened:
- **HDD file overwrite** — real: one pass, that file's blocks are unrecoverable.
- **SSD file overwrite** — **best-effort only.** We say so every time, and point you to the vault.
- **Vault crypto-erase** — **truly unrecoverable**, on two honest conditions: the data must have entered the vault
  encrypted (we can't un-write plaintext that already hit the flash), and the key must never have leaked (no key backup,
  no copy paged to swap/hibernation). Miss either and the guarantee is void — so the design is built to hold both (a
  passphrase-derived key that's never written to disk, and a vault re-key on every shred).
- **Whole-drive disposal** — we print the exact vendor secure-erase / sanitize command; we don't wrap a drive-wipe we
  can't verify.

> **Status:** overwrite + detection + guards ship today (below); the **crypto-erase vault is in active development** —
> it's the headline SSD answer and the reason this tool exists. Design + rationale: [PLAN.md](PLAN.md).

## Honest per-device capability matrix
| Storage / FS | File overwrite | Honest claim | Correct primitive |
|---|---|---|---|
| **HDD, in-place FS** | reliable (1 pass) | "current blocks overwritten; recovery infeasible" | overwrite + free-space wipe |
| **SSD / NVMe / flash** | **unreliable** | **never "unrecoverable"** | **crypto-erase**; whole-drive sanitize for disposal |
| **CoW/snapshot FS** (btrfs/ZFS/APFS/ReFS) | old blocks pinned by snapshots | "current blocks only" | crypto-erase; delete snapshots first |
| **NTFS resident/compressed/sparse** | reallocated | (handled) | SDelete-style cluster overwrite + free-MFT fill |

Default is **one pass** — multi-pass "Gutmann/DoD" is obsolete theater on modern drives (NIST, and Gutmann himself, say
so). Secure Delete also **discloses**, rather than silently claiming to cover, the side-channels a file wipe can't reach:
VSS shadow copies, pagefile/hiberfil, temp/caches/thumbnails, `$LogFile`/`$UsnJrnl`, directory-slack filenames, and SSD
spare/over-provisioned area.

## What works today (v0.2 — Rust)
- **Quiet free-space clean** — `clean` a volume's free space now (overwrite it, and the SSD reclaims/TRIMs it when the
  fill is removed), and `service` to keep doing it on a schedule so your normal deletions get **completed automatically**.
  A dynamic safety margin is always kept, and the system volume is refused unless you opt in.
- **The crypto-erase vault** — `init` · `add` · `list` · `open` · `shred`; shred destroys a file's key + re-keys the vault
  → unrecoverable **even on an SSD**.
- **Per-file overwrite** — `overwrite` a single file (real on HDD; best-effort on SSD), behind a confirmation gate.
- **Memory-safe Rust**, keys in `zeroize`d buffers, vetted crypto (RustCrypto **AES-256-GCM** + **Argon2id**), one
  self-contained binary.

Being ported from **v0.1** (Python, tagged [`v0.1.0`](https://github.com/LxveAce/secure-delete/tree/v0.1.0)): media/
filesystem detection and the advisory whole-drive sanitize command. Roadmap: [PLAN.md](PLAN.md).

## Try it
```
cargo build --release

# quiet mode — the install-time deep clean + the scheduled sweep:
secure-delete clean   ./folder                         # dry-run: shows the plan (writes nothing)
secure-delete clean   ./folder --execute               # do it (add --allow-system-volume for C:/ or /)
secure-delete service ./folder --interval 3600         # live quietly: clean now, then hourly

# vault mode — a guarantee even on SSD:
export SECURE_DELETE_PASSPHRASE="your passphrase"
secure-delete init  ./myvault
secure-delete add   ./myvault ./secret.pdf             # encrypted the moment it enters
secure-delete shred ./myvault <id>                     # destroy the key -> unrecoverable

cargo test
```

## Run it quietly (the intended setup)
"Lives quietly" = let your OS scheduler run `secure-delete service`:
- **Linux (systemd):** a unit running `secure-delete service /home --interval 21600`, enabled at boot.
- **Windows (Task Scheduler):** a task running `secure-delete.exe service C:\ --interval 21600 --allow-system-volume` at logon.

A one-click installer that registers the service and runs the first deep clean is on the roadmap; today it's the two lines above.

## Roadmap
- **v0.1 (Python)** — per-file overwrite + guards + media/FS detection + free-space + advisory sanitize. Tagged `v0.1.0`.
- **v0.2 (Rust) ← here** — **quiet free-space clean + service** · the **crypto-erase vault** (`init`/`add`/`list`/`open`/`shred`) · per-file overwrite.
- **Next** — a one-click installer (registers the service + runs the first deep clean); port media/FS detection + advisory
  sanitize; a whole-vault re-key (passphrase change) + a TPM/token-backed root for a hardware-guaranteed shred; a desktop GUI.

Design rationale + the full plan: [PLAN.md](PLAN.md). Safety posture: [SAFETY.md](SAFETY.md).

## Guardrails
For your own or authorized data only · SAFE-by-default · honest per-device claims · no destructive code until reviewed and
gated · no telemetry, works offline.

---
Built by **LxveAce** · part of **[LxveLabs](https://lxvelabs.com)**. Questions or ideas → **[Discord](https://discord.gg/lxvelabs)** or open an issue.
