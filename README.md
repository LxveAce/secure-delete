# Secure Delete

> **Make deleted data actually unrecoverable — honestly, per device.**
> Crypto-erase first · overwrite where it's real (HDD) · never a false promise.

[![License: MIT](https://img.shields.io/github/license/LxveAce/secure-delete)](LICENSE)
[![Stars](https://img.shields.io/github/stars/LxveAce/secure-delete?style=social)](https://github.com/LxveAce/secure-delete/stargazers)

**[Cyber Controller](https://cybercontroller.org)** · **[LxveLabs](https://lxvelabs.com)** · **[Discord](https://discord.gg/lxvelabs)**

A secure-deletion primitive + CLI from **LxveAce / LxveLabs**. When you delete a file, make the original data genuinely
unrecoverable while the space returns as normal free space — the reusable "secure delete" building block every LxveLabs
product can call. Same lineage as `shred` / `sdelete` / BleachBit / VeraCrypt: **for your own or authorized data only.**

> [!WARNING]
> **Early build — SAFE by default.** It **detects and plans** (dry-run) but ships **no destructive code yet**: the erase
> methods are guarded and `execute()` refuses. It won't delete anything until the real erase paths are built behind an
> explicit confirm gate. See [SAFETY.md](SAFETY.md).

## The one idea that shapes everything
Overwriting a deleted file works on a **magnetic HDD** but is **unreliable on an SSD** — the flash translation layer sends
your overwrite to a *different* physical cell and leaves the original in spare NAND the OS can't even address (proven by
UC San Diego, USENIX FAST'11; TRIM is only a hint, not an erase). The robust, media-independent guarantee is
**cryptographic erase: keep data encrypted at rest, and "delete" by destroying the key** (NIST SP 800-88 Purge-level,
instant). So Secure Delete **leads with crypto-erase** and uses overwrite as an honest **HDD-only** supplement — and it
**never prints a bare "unrecoverable."** Every claim is scoped to what the mechanism actually did, on the drive you have.

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
- **Read-only detection** of media (HDD vs SSD) + filesystem — Linux (`findmnt` / `lsblk`) and Windows
  (`Get-Volume` / `Get-Partition` / `Get-PhysicalDisk`). Verified on real hardware.
- The **honest routing + claim engine** (dry-run): picks crypto-erase on SSD / copy-on-write / unknown media, overwrite
  only on HDD + in-place FS, and surfaces the residual copies that may survive.
- A **CLI** — `detect` and `file` — dry-run only, destroys nothing.

## Try it (safe — plans only)
```
PYTHONPATH=src python -m secure_delete.cli detect ./README.md   # read-only: what media + FS did it find?
PYTHONPATH=src python -m secure_delete.cli file ./README.md     # the honest erase plan (destroys nothing)
python -m pytest tests/                                         # detection routing + honesty + safety guards
```

## Roadmap
`P0` research + design ✅ · `P1` detection ✅ + the reviewed, confirm-gated HDD overwrite / free-space wipe · `P2`
crypto-erase (the headline) + whole-drive sanitize + SSD routing · `P3` Dead Man's Switch key-destruction integration
(gated) · `P4` cross-product overwrite-on-uninstall + a desktop GUI (Windows/Linux).

Design rationale + the full plan: `PLAN.md`. Safety posture: `SAFETY.md`.

## Guardrails
For your own or authorized data only · SAFE-by-default · honest per-device claims · no destructive code until reviewed and
gated · no telemetry, works offline.

---
Built by **LxveAce** · part of **[LxveLabs](https://lxvelabs.com)**. Questions or ideas → **[Discord](https://discord.gg/lxvelabs)** or open an issue.
