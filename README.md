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
- **HDD** — overwrite is real: one pass, that file's blocks are gone.
- **SSD** — overwriting can't reliably reach the flash (and it just wears the drive), so on SSD the quiet clean issues
  **TRIM** — it removes deleted data from the drive's host-visible read path, but the physical erase is the controller's
  to schedule, not a verifiable wipe. The **real protection on an SSD is full-disk encryption** (then deleted residue is
  already ciphertext). **`secure-delete status`** tells you whether your drive is actually encrypted + TRIM-enabled, and
  what to fix if not.
- **Vault crypto-erase** — a per-file guarantee even on SSD, on two honest conditions: the data entered the vault
  encrypted (no retroactive plaintext), and the key never leaked (no backup; no copy paged to swap/hibernation).
- **Whole-drive disposal** — the drive's own hardware secure-erase (NVMe / ATA **Sanitize**) is the NIST-grade wipe; we
  point you at it rather than pretend an overwrite did it.

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
- **`status` — the honest advisor.** Per volume, it tells you whether deleted data is actually protected: media (HDD/SSD),
  full-disk-encryption state (+ scope), and TRIM — with plain advice (on an unencrypted SSD it tells you to enable FDE,
  because overwriting can't save you there). Plus `detect` (media + filesystem).
- **Quiet clean, media-aware.** `clean` **overwrites** free space on an **HDD** and issues **TRIM** on an **SSD** (no
  wear, no false promise); `service` keeps it running on a schedule so normal deletions get completed automatically.
- **The crypto-erase vault** — `init` · `add` · `list` · `open` · `shred` · **`rekey`**. Shred a key → unrecoverable even
  on an SSD; `rekey` (change the passphrase) is a **whole-vault crypto-erase** that invalidates all old key material —
  the strong way to close any stale key residue an SSD may have left in flash.
- **Per-file overwrite** — `overwrite` a single file (real on HDD; best-effort on SSD), behind a confirmation gate.
- **Memory-safe Rust**, keys in `zeroize`d buffers, vetted crypto (RustCrypto **AES-256-GCM** + **Argon2id**), one
  self-contained binary.

Being ported from **v0.1** (Python, tagged [`v0.1.0`](https://github.com/LxveAce/secure-delete/tree/v0.1.0)): media/
filesystem detection and the advisory whole-drive sanitize command. Roadmap: [PLAN.md](PLAN.md).

## Try it
```
cargo build --release

# is your drive actually protected? (the honest advisor)
secure-delete status ./folder
secure-delete detect ./folder

# quiet mode — media-aware: overwrite on HDD, TRIM on SSD:
secure-delete clean   ./folder                         # dry-run: shows the plan (writes nothing)
secure-delete clean   ./folder --execute               # do it (add --allow-system-volume for C:/ or /)
secure-delete service ./folder --interval 3600         # live quietly: clean now, then hourly

# vault mode — a guarantee even on SSD:
export SECURE_DELETE_PASSPHRASE="your passphrase"
secure-delete init  ./myvault
secure-delete add   ./myvault ./secret.pdf             # encrypted the moment it enters
secure-delete shred ./myvault <id>                     # destroy the key -> unrecoverable
SECURE_DELETE_NEW_PASSPHRASE="new" secure-delete rekey ./myvault   # whole-vault crypto-erase (change passphrase)

cargo test
```

## Run it quietly (the intended setup)
"Lives quietly" = let your OS scheduler run `secure-delete service`:
- **Linux (systemd):** a unit running `secure-delete service /home --interval 21600`, enabled at boot.
- **Windows (Task Scheduler):** a task running `secure-delete.exe service C:\ --interval 21600 --allow-system-volume` at logon.

A one-click installer that registers the service and runs the first deep clean is on the roadmap; today it's the two lines above.

## Roadmap
- **v0.1 (Python)** — per-file overwrite + guards + media/FS detection + free-space + advisory sanitize. Tagged `v0.1.0`.
- **v0.2 (Rust) ← here** — the **`status` advisor** + media-aware **quiet clean** (overwrite HDD / TRIM SSD) · the
  **crypto-erase vault** (`init`/`add`/`list`/`open`/`shred`) · per-file overwrite.
- **v0.2.3** — a whole-vault **`rekey`** (passphrase change = whole-vault crypto-erase) — the software way to close the
  SSD key residue.
- **Next** — a one-click installer (register the service + first deep clean); hardware disposal (NVMe/ATA **Sanitize**
  crypto-erase); a **TPM / Secure-Enclave-backed vault root** for a *hardware-guaranteed* shred (closes the residual even
  if the old passphrase is known); transparent per-file crypto via **fscrypt** (a "protected folder", no manual vault); a desktop GUI.

Design rationale + the full plan: [PLAN.md](PLAN.md). Safety posture: [SAFETY.md](SAFETY.md).

## Guardrails
For your own or authorized data only · SAFE-by-default · honest per-device claims · no destructive code until reviewed and
gated · no telemetry, works offline.

---
Built by **LxveAce** · part of **[LxveLabs](https://lxvelabs.com)**. Questions or ideas → **[Discord](https://discord.gg/lxvelabs)** or open an issue.
