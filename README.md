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
> **This tool permanently erases data** — but it is **SAFE by default.** Everything is a dry-run unless you pass
> `--execute`, which then requires you to **type the exact target path** to confirm. It refuses system paths, symlinks,
> and non-files. Per-file overwrite and free-space wipe are real; whole-drive erase is **advisory** (it prints the OS
> command, runs nothing). **For your own or authorized data only.** See [SAFETY.md](SAFETY.md).

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
