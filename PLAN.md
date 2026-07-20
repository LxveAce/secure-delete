# secure-delete — refined implementation plan (P1 spec)

Refines the vault design-log (`03-Projects/Secure-Delete/Secure-Delete.md`) into a concrete build order. Scope here is
**P1: the primitive + a CLI.** Later phases (crypto-erase, DMS integration, GUI) are sketched at the end.

## Non-negotiables (carried from the design)
1. **Crypto-erase is the headline; overwrite is an HDD-only supplement.** The engine must route by media.
2. **Never a bare "unrecoverable."** Every operation returns a `ScopedResult` whose `claim` is scoped to what actually happened, with `residuals` listing surviving-copy channels + how to close them.
3. **SAFE-by-default.** Dry-run is the default; execution is a separate, explicit, gated step. The scaffold ships **no destructive code**.
4. **Orchestrate proven tools, don't reinvent** raw block overwrite.
5. **Own/authorized data only**; honest, defensive framing throughout.

## The primitive API (contract)
```
detect.probe(path) -> TargetInfo{ path, device, media: HDD|SSD_FLASH|UNKNOWN, filesystem, cow: bool, notes[] }
engine.plan(path, method='auto') -> ScopedResult(performed=False)   # dry-run: what WOULD happen + honest claim
engine.execute(plan, confirm_token) -> ScopedResult(performed=True) # GATED — not implemented in the scaffold
result.ScopedResult{ target, media, filesystem, method, performed, claim, residuals[], warnings[] }
```
`method` ∈ `auto | overwrite | crypto_erase | freespace_wipe | whole_drive_sanitize`. `auto` picks the honest method
from the detected media/FS (HDD in-place FS → overwrite; SSD or CoW → crypto_erase or "best-effort + advise crypto").

## Build order within P1
1. **`result.py`** — the `ScopedResult` dataclass + claim/residual builders. Pure logic, fully unit-testable. **(scaffolded)**
2. **`detect.py`** — read-only media + filesystem detection.
   - Linux: map path→device (`findmnt -no SOURCE --target`), rotational (`/sys/block/<dev>/queue/rotational`), FS type (`findmnt -no FSTYPE`); flag CoW (btrfs/zfs), ext journal mode.
   - Windows: `Get-PhysicalDisk`/`Get-Partition`/`Get-Volume` (MediaType, FileSystem); flag ReFS.
   - Unknown → most-conservative claim. **(✅ Linux + Windows real detection DONE + verified live 2026-07-20 — Windows via Get-Volume/Get-Partition/Get-PhysicalDisk MediaType; detected this box as SSD/NTFS)**
3. **`methods.py`** — the erase methods as **guarded stubs** (raise `NotImplementedError` with the intended tool + a safety note). No destruction until reviewed + gated. **(scaffolded — stubs only)**
4. **`engine.py`** — `plan()` (real, safe: detect → choose method → build ScopedResult) + `execute()` (guarded: refuses in the scaffold). **(scaffolded)**
5. **`cli.py`** — `--dry-run` DEFAULT; subcommands `file`, `freespace`, `sanitize`; prints the plan + honest caveats; `--execute` currently refuses (points at SAFETY.md). **(scaffolded)**
6. **`tests/`** — detection logic, the result-contract's honesty (no bare "unrecoverable"; SSD never claims unrecoverable), and that `execute` is guarded. **(scaffolded)**

## Test matrix (honesty is the thing under test)
- SSD/flash target ⇒ `method != overwrite-as-final` AND `claim` never contains "unrecoverable" unwqualified.
- CoW filesystem ⇒ `residuals` mentions snapshots.
- HDD + in-place FS ⇒ overwrite plan allowed; claim scoped to "current blocks."
- Any `execute()` call in the scaffold ⇒ raises/refuses (guard test).
- `plan()` is pure/read-only ⇒ never touches the target.

## Later phases (out of P1 scope — sketched)
- **P2 crypto-erase:** manage an encrypted container/volume (LUKS/VeraCrypt/BitLocker) and destroy the key; SSD routing (best-effort overwrite + TRIM, *labeled*); whole-drive ATA-Secure-Erase / NVMe-Sanitize for disposal (verify, don't trust — FAST'11 firmware bugs). Side-channel cleanup (consent-gated, each destructive step opt-in).
- **P3 DMS integration:** the wipe path destroys keys (crypto-erase). **Owner + HW-gated (irreversibility gate).**
- **P4:** cross-product overwrite-on-uninstall hook (detached-helper design in the vault note) + a standalone GUI (Win/Linux).

## Open decisions (owner) — see HANDOFF.md
Product name · graduate to own repo + public/private · language commit (Python scaffold; Rust/Go rewrite optional for ship) · crypto-at-rest adoption across products (the real enabler) · free vs paid · how far to take destructive side-channel cleanup.
