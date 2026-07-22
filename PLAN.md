# secure-delete: refined implementation plan (P1 spec)

> **Status 2026-07-20 (v0.1.0):** P1 is BUILT + verified live: real per-file overwrite (+ name-obscure + delete) and
> free-space wipe, both behind `guards` (refuse system paths / symlinks / non-files) and an **exact-match confirmation
> gate**; whole-drive sanitize / crypto-erase are **advisory** (print the command, run nothing). 23 tests green. A
> throwaway file was really erased on a live box; the gate held on a wrong confirmation. Next: P2 (container crypto-erase).

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
1. **`result.py`:** the `ScopedResult` dataclass + claim/residual builders. Pure logic, fully unit-testable. **(scaffolded)**
2. **`detect.py`:** read-only media + filesystem detection.
   - Linux: map path→device (`findmnt -no SOURCE --target`), rotational (`/sys/block/<dev>/queue/rotational`), FS type (`findmnt -no FSTYPE`); flag CoW (btrfs/zfs), ext journal mode.
   - Windows: `Get-PhysicalDisk`/`Get-Partition`/`Get-Volume` (MediaType, FileSystem); flag ReFS.
   - Unknown → most-conservative claim. **(✅ Linux + Windows real detection DONE + verified live 2026-07-20, Windows via Get-Volume/Get-Partition/Get-PhysicalDisk MediaType; detected this box as SSD/NTFS)**
3. **`methods.py`:** the erase methods as **guarded stubs** (raise `NotImplementedError` with the intended tool + a safety note). No destruction until reviewed + gated. **(scaffolded, stubs only)**
4. **`engine.py`:** `plan()` (real, safe: detect → choose method → build ScopedResult) + `execute()` (guarded: refuses in the scaffold). **(scaffolded)**
5. **`cli.py`:** `--dry-run` DEFAULT; subcommands `file`, `freespace`, `sanitize`; prints the plan + honest caveats; `--execute` currently refuses (points at SAFETY.md). **(scaffolded)**
6. **`tests/`:** detection logic, the result-contract's honesty (no bare "unrecoverable"; SSD never claims unrecoverable), and that `execute` is guarded. **(scaffolded)**

## Test matrix (honesty is the thing under test)
- SSD/flash target ⇒ `method != overwrite-as-final` AND `claim` never contains "unrecoverable" unwqualified.
- CoW filesystem ⇒ `residuals` mentions snapshots.
- HDD + in-place FS ⇒ overwrite plan allowed; claim scoped to "current blocks."
- Any `execute()` call in the scaffold ⇒ raises/refuses (guard test).
- `plan()` is pure/read-only ⇒ never touches the target.

## Later phases (out of P1 scope, sketched)
- **P2, the crypto-erase vault (the SSD solve, in development).** The honest way to give SSD users real per-file unrecoverability (overwrite can't: FTL / wear-leveling). NIST SP 800-88r2 recognizes **cryptographic erase** as a Purge method; Apple's Effaceable Storage is the reference ("erasing the key renders all files cryptographically inaccessible"). Design:
  - **Managed vault, encrypt-on-INGEST** (never encrypt-existing-in-place): files are encrypted as they enter, so plaintext never lands on flash as a normal file. NIST's hard precondition: CE is void if plaintext was ever written.
  - **Per file:** a random 256-bit DEK; AEAD (AES-256-GCM or ChaCha20-Poly1305) with a **unique nonce** per file/segment (GCM nonce reuse is catastrophic) + auth tag.
  - **Keystore:** each DEK wrapped under a master KEK (AES Key Wrap, RFC 3394/5649); the master KEK is derived from the user passphrase via **Argon2id** and **never persisted in plaintext** (commodity SSDs have no effaceable hardware, so the root secret must be un-persisted or in a TPM/token).
  - **Shred a file = drop its DEK AND re-key the whole vault** (fresh master, re-wrap only survivors, atomic swap, destroy the old master), so any stale wrapped-DEK copy the FTL scattered across flash is now under a **dead** key = permanent noise. This concentrates "must be reliably destroyed" to one small root secret.
  - **Honesty gates (keep the "unrecoverable" claim true):** only data that entered encrypted (no retroactive plaintext); keys never leak (no backup/escrow; guard swap/hibernation via mlock + zeroize); against a nation-state NIST still says physically destroy. Sources: NIST SP 800-88r2, Apple Platform Security, Wei et al. FAST'11, Meijer & van Gastel (CVE-2018-12038, a real self-encrypting drive that failed exactly this way).
  - Whole-drive ATA-Secure-Erase / NVMe-Sanitize stays **advisory**; per-file SSD overwrite stays **labeled best-effort**.
- **P3 DMS integration:** the wipe path destroys keys (crypto-erase). **Owner + HW-gated (irreversibility gate).**
- **P4:** cross-product overwrite-on-uninstall hook (detached-helper design in the vault note) + a standalone GUI (Win/Linux).

## The honest SSD strategy (grounded 2026-07-20)
Overwriting flash is futile (FTL) **and** counterproductive (wear). NIST says avoid it. So, per media:
- **HDD:** overwrite is real. `clean`/`overwrite` do it.
- **SSD everyday:** **TRIM** (not overwrite): removes deleted data from the host read path; NOT a host-verifiable physical
  erase. The **real protection is full-disk encryption** (deleted residue = ciphertext). `status` detects FDE + TRIM and
  advises. Neither TRIM nor overwrite is on NIST/IEEE-2883's Clear/Purge lists for flash.
- **SSD guaranteed (per file):** the **crypto-erase vault** (destroy the key). Residual on a commodity SSD = a stale
  wrapped-master slot → closed by a **hardware KEK** (TPM 2.0 evict / Secure Enclave), on the roadmap.
- **SSD disposal:** the drive's **hardware Sanitize** (NVMe Format/Sanitize crypto-erase, ATA Secure Erase on an SED,
  LUKS `luksErase` / OPAL factory-reset). NIST Purge. Advisory today; a wrapped command next.
- **Honesty:** never "unrecoverable" for TRIM/overwrite on SSD; FDE = "ciphertext at rest, protected when off/locked, NOT
  on a live unlocked system"; crypto-erase = "protected now, not forever" (quantum); verification is trust-based.
- **Two-tier claims:** Tier 1 "made inaccessible" (key/entry dropped, best-effort residual) vs Tier 2 "hardware-guaranteed
  destroyed" (TPM/SEP evict, or drive Sanitize). Never merge them into one "unrecoverable."

## Language (recommended: Rust)
A grounded eval (C / Rust / Go / Python for this exact tool) points to **Rust**. The vault's whole job is destroying key
material, which needs reliable secret-zeroing (`zeroize` / `secrecy`). Go's GC can copy a key to unwipeable memory (its
fix is Linux-only + experimental; this tool is Win+Linux), C adds the memory-unsafety class we exist to prevent, and
Python can't zero secrets or ship a trustworthy single binary. Field precedent: modern key tools (`rage`, `ripgrep`) are
Rust; the old disk tools (`shred`, `cryptsetup`, VeraCrypt) are C. The Python v0.1 here is an **executable spec**, not code
to preserve. _Toolchain note:_ `rustup` isn't installed on the current dev box (only Go is). Building Rust needs a
toolchain install or CI-based verification.

## Open decisions (owner): see HANDOFF.md
Confirm the **Rust** rewrite (+ how to build: install `rustup` vs CI-verify) · crypto-at-rest adoption across products
(the real enabler) · free vs paid · how far to take destructive side-channel cleanup.
