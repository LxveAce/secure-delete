# Secure Delete

> **When you delete a file, it's not actually gone.** Secure Delete makes it gone — honestly, and even on an SSD.

[![License: MIT](https://img.shields.io/github/license/LxveAce/secure-delete)](LICENSE)
[![Stars](https://img.shields.io/github/stars/LxveAce/secure-delete?style=social)](https://github.com/LxveAce/secure-delete/stargazers)

**[Cyber Controller](https://cybercontroller.org)** · **[LxveLabs](https://lxvelabs.com)** · **[Discord](https://discord.gg/lxvelabs)**

A secure-deletion tool from **LxveAce / LxveLabs** — for your own or authorized data only. Same lineage as `shred` /
`sdelete` / BleachBit / VeraCrypt, built on one honest idea: **make the data truly gone, and never claim more than the
hardware can actually deliver.**

> [!WARNING]
> **This tool permanently erases data** — but it is **SAFE by default.** Everything is a dry-run unless you pass
> `--execute`, which then requires you to **type the exact target path** to confirm. It refuses system paths, symlinks,
> and non-files. Per-file overwrite and free-space wipe are real; whole-drive erase is **advisory** (it prints the OS
> command, runs nothing). **For your own or authorized data only.** See [SAFETY.md](SAFETY.md).

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

## Our answer: destroy the *key*, not the bytes
You can't reliably erase the bytes on an SSD — so don't chase them. **Encrypt each file with its own random key the moment
it enters the Secure Delete vault; to "shred" it, destroy that key** (and re-key the vault). The ciphertext scattered
across the flash instantly becomes permanent noise — truly unrecoverable, without overwriting a single cell. This is
**cryptographic erase**, a method NIST recognizes (SP 800-88r2), and it's how Apple wipes an iPhone in seconds: *"erasing
the key renders all files cryptographically inaccessible."*

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

## What works today
- **Real per-file secure erase** — overwrite the file's bytes, obscure its name, delete it — behind a hard **guard**
  (refuses system paths / symlinks / non-files) and an **exact-match confirmation gate** (you type the full path).
- **Free-space wipe** — fill unallocated space with random data (leaving a safety margin) then remove it, to erase
  previously-deleted file data. Confirm-gated.
- **Advisory whole-drive sanitize / crypto-erase** — prints the exact `nvme` / `hdparm` / `cryptsetup` command for the
  detected drive and **runs nothing** (a drive wipe is too dangerous to wrap-and-run).
- **Read-only detection** of media (HDD vs SSD) + filesystem — Linux (`findmnt`/`lsblk`) and Windows (`Get-PhysicalDisk`).
- **Honest routing + claims** — crypto-erase recommended on SSD / copy-on-write / unknown media; overwrite is labeled
  best-effort on flash; never a bare "unrecoverable"; residual copies are always disclosed.

## Try it
```
# safe (default) — plans + detection, destroys nothing:
PYTHONPATH=src python -m secure_delete.cli detect ./README.md        # read-only: what media + FS?
PYTHONPATH=src python -m secure_delete.cli file ./README.md          # the honest erase PLAN (dry-run)
PYTHONPATH=src python -m secure_delete.cli sanitize ./README.md      # advisory: the whole-drive command

# real erase (asks you to type the exact path to confirm) — use ONLY on your own data:
PYTHONPATH=src python -m secure_delete.cli file /path/to/junk.txt --execute

python -m pytest tests/                                              # 29 tests: erase, guards, gate, honesty
```

## Roadmap
`P0` design ✅ · `P1` detection ✅ + confirm-gated per-file overwrite ✅ + free-space wipe ✅ + advisory sanitize ✅ · `P2`
container crypto-erase (encrypt-then-destroy-key) + verified whole-drive sanitize · `P3` Dead Man's Switch key-destruction
integration (gated) · `P4` cross-product overwrite-on-uninstall + a desktop GUI (Windows/Linux).

Design rationale + the full plan: `PLAN.md`. Safety posture: `SAFETY.md`.

## Guardrails
For your own or authorized data only · SAFE-by-default · honest per-device claims · no destructive code until reviewed and
gated · no telemetry, works offline.

---
Built by **LxveAce** · part of **[LxveLabs](https://lxvelabs.com)**. Questions or ideas → **[Discord](https://discord.gg/lxvelabs)** or open an issue.
