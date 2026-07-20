# SAFETY — why this scaffold destroys nothing (yet)

`secure-delete` **permanently destroys data by design.** That is the whole point of the tool — and exactly why the
scaffold ships with **no working destruction** and is built SAFE-by-default. Read this before wiring any real erase.

## Posture in the scaffold
- **No destructive code exists.** Every method in `methods.py` is a guarded stub that raises `NotImplementedError`.
- **Dry-run is the default and the only thing that runs.** `engine.plan()` and the CLI only *describe* what would happen
  (detection is read-only). `engine.execute()` refuses in the scaffold.
- **Detection is read-only** — it reads `/sys`, `findmnt`, volume metadata. It never writes to the target.

## Rules for anyone implementing the real erase (later, gated)
1. **Own / authorized data only.** This is privacy tooling in the `shred` / `sdelete` / BleachBit / VeraCrypt lineage — for
   protecting data the user owns, not for evading lawful process or destroying others' data.
2. **Honest claims, always scoped.** Never emit an unqualified "unrecoverable." On SSD/flash and CoW filesystems, file
   overwrite is best-effort — say so. The robust guarantee is crypto-erase; prefer it.
3. **Confirm + double-gate destruction.** Real execution must require an explicit target confirmation, must default to
   non-destructive, must verify the target is what the user meant (not a system/mounted-in-use path), and must back up or
   refuse on ambiguity. No silent/auto destruction.
4. **Orchestrate proven tools** (sdelete / cipher / shred / blkdiscard / hdparm / nvme / cryptsetup) rather than hand-rolling
   raw disk overwrite — they already handle the resident-file / firmware-sanitize edge cases.
5. **Verify, don't trust.** Firmware sanitize commands have known bugs (FAST'11) — verify erasure, never assume success.
6. **Dead Man's Switch integration is separate and gated.** Any destruct-path change goes through the `Operating-Rules`
   irreversibility gate: ready patch → owner sign-off → HW-validate on a designated spare board → commit. Never auto-push.
7. **No PII, no secrets** committed. LxveAce identity, human voice.

## The self-cleaning uninstaller (design-level only here)
The overwrite-on-uninstall step (a detached helper that outlives the app, then erases + removes the app's files including
itself) is described at the architecture level in the vault design-log. It is **not implemented here**, and the concrete
self-deleting helper is an authorization-gated implementation detail (a prior automated-research pass on this sub-topic
tripped a cyber-safeguard — logged in `command-center/SAFEGUARDS-LOG.md`, 2026-07-18).
