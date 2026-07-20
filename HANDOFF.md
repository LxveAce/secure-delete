# ▶ HANDOFF — pick up here (secure-delete scaffold)

_Written 2026-07-18 (`pcb` lane, Fable 5). Owner promoted the idea ("continue… refining a plan, and starting scaffolding")
and asked for everything logged + pushed so it's pickable-up at home._

## Where everything lives (all committed + pushed to GitHub)
- **This repo — the canonical home:** `LxveAce/secure-delete` (**PUBLIC, MIT**). Graduated out of command-center 2026-07-20.
- **Design-log + rationale (Obsidian):** vault `03-Projects/Secure-Delete/Secure-Delete.md` (also in the `lxvelabs-vault` repo).
- **Idea capture (verbatim owner words) + researched plan:** `command-center/projects/ideas/secure-delete.md`.
- **Incubator entry:** `command-center/projects/ideas/IDEA-INCUBATOR.md` (row #1).
- **Safeguard note:** `command-center/SAFEGUARDS-LOG.md` (2026-07-18).

## State right now
- **Scaffold = design + interfaces + read-only detection + a dry-run CLI. NO destructive code.** See `SAFETY.md`.
- Grounded research done (NIST 800-88, UCSD FAST'11 cited). **Thesis: crypto-erase first; overwrite is HDD-only supplement; never a bare "unrecoverable."**
- **2026-07-20: Windows detection wired + verified live** — `detect` correctly reads this machine as Disk0 / **SSD** / **NTFS**, and the dry-run routes an SSD file to **crypto-erase** (not overwrite) with NTFS residuals surfaced. Linux uses `findmnt`/`lsblk` (rotational). **14/14 tests green.**

## Try it (safe)
```
cd secure-delete
PYTHONPATH=src python -m secure_delete.cli detect ./README.md   # read-only: shows detected media + FS
PYTHONPATH=src python -m secure_delete.cli file ./README.md     # prints the honest plan (destroys nothing)
python -m pytest tests/                                             # 14 tests: detection routing + honesty + safety guards
```

## ▶ Next steps (in order)
1. ✅ **Graduated 2026-07-20** — named **Secure Delete** (by LxveAce / LxveLabs), **PUBLIC** repo `LxveAce/secure-delete`, **MIT**, Python. (A Rust/Go rewrite of the shipped tool stays an optional future call.)
2. **P1 build-out** (per `PLAN.md`): ✅ real detection (Linux + Windows) DONE + verified. Next — the *reviewed + gated* HDD overwrite + free-space wipe by orchestrating `sdelete`/`shred` (SAFE-by-default, confirm-gated), still no auto-destruction.
3. **P2:** crypto-erase (the real headline) + SSD routing + whole-drive sanitize.
4. **P3:** DMS key-destruction integration — **irreversibility-gated** (owner sign-off → spare-board HW-validate).
5. **Portfolio enabler decision:** adopt crypto-at-rest across products so "secure delete = destroy the key" everywhere.

## Guardrails (unchanged)
Own/authorized data only · SAFE-by-default · honest per-device claims · no destructive code until reviewed + owner-gated ·
LxveAce identity, no PII · DMS destruct-path behind the irreversibility gate.
