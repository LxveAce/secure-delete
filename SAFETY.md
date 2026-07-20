# SAFETY

`secure-delete` **permanently destroys data by design** — that's the whole point. It's built to be careful. This is the posture and the honest limits.

## v0.3 (Rust) — current posture
- **Dry-run defaults.** `overwrite` does nothing without `--execute` + a matching `--confirm`; it refuses symlinks and non-files.
- **The vault destroys the key, not the bytes.** `shred` drops a file's key and re-keys the vault. Honest residual on a commodity **software** vault (no effaceable hardware): a stale copy of the *old wrapped-master* could linger in flash — recovering a shredded file would need that tiny slot from unaddressable NAND *and* the passphrase. Far harder than recovering a plaintext file, but not a hardware-guaranteed zero (a passphrase change closes it in software).
- **Optional TPM root (`init --tpm`) closes that residual in hardware.** The master is wrapped under `HKDF(RWK ‖ KEK)` where RWK is sealed by the TPM; `hardware-shred` destroys the TPM key so a stale wrapped-master in flash can't be opened even with the passphrase. **Honest limit by platform:** on **Windows** (Platform Crypto Provider) the TPM key is an SRK-wrapped `.PCPKEY` blob on disk, usable only on *this* TPM — deleting it is defense-in-depth (a remote flash-image + passphrase attacker is defeated), **not** an absolute in-chip erase. On **Linux** (`tpm2-tools`) the RWK is sealed into a **persisted, evictable** TPM object (never wrapped on disk; transient blobs kept in `/dev/shm`), so eviction is a *true* in-hardware erase — the stronger case. macOS Secure Enclave is designed, not yet built. A tampered header can't downgrade a TPM vault to software (the master seal binds the root descriptor as AEAD AAD). A **mandatory one-time recovery code** (unless `--i-understand-total-loss`) survives TPM loss; guard it like the data (code + vault folder + passphrase reopens it).
- **A TPM vault is bound to one machine.** A TPM clear, firmware reset, or hardware change makes it unopenable except via the recovery code — copying the vault folder is *not* a backup. `vault-status` reports the true state (reachable / key-gone / TPM-unreachable) and never a bare "unrecoverable".
- **Keys** live in `zeroize`d buffers and are never written to disk in the clear; vetted crypto (RustCrypto AES-256-GCM + Argon2id + HKDF-SHA256). **Residual we do *not* claim to scrub:** while a file is open its plaintext (and the unsealed master) live in RAM, which the OS can page to the pagefile/hiberfil — for a high-value vault, encrypt the pagefile (`fsutil behavior set encryptpagingfile 1`) and disable hibernation. The shred guarantee covers content never decrypted into RAM on this machine.
- **Own / authorized data only.** No telemetry; works offline.

## Design posture (from v0.1 — Python, tagged `v0.1.0`; the principles still hold)
- **Destruction is real but gated.** Per-file overwrite + free-space wipe are implemented. They run ONLY via
  `engine.execute` / `engine.execute_freespace`, each of which first runs the `guards` checks (refuse system paths,
  symlinks, non-files) AND an **exact-match confirmation** (the caller must supply the resolved target path).
- **Dry-run is the default.** `engine.plan()` + the CLI without `--execute` only describe what would happen. `--execute`
  triggers an interactive prompt to type the exact path (or `--confirm <path>` for scripts).
- **Whole-drive ops are advisory** — `crypto_erase_advice` / `whole_drive_sanitize_advice` return the OS command and run nothing.
- **Detection is read-only** — reads `/sys`, `findmnt`/`lsblk`, or `Get-*` cmdlets; never writes to the target.

## Red-team hardening (2026-07-20)
An adversarial review drove these fixes (all covered by tests):
- Protected-root logic no longer treats `/` as an ancestor (a normal file is erasable on Linux) and now **refuses files
  sitting directly in a volume/drive root** (e.g. `C:\bootmgr`); `SystemRoot` has a hard `C:\Windows` fallback.
- **Free-space wipe refuses the SYSTEM/boot volume** unless `--allow-system-volume`, and always keeps a dynamic margin
  (≥ max(1 GiB, 10% of volume)); it writes one growable fill file and **verifies cleanup**, warning loudly on leftover.
- Per-file overwrite opens a **validated fd (`O_NOFOLLOW`)** and re-checks it's a regular file, closing the check→open
  swap window (TOCTOU).
- A plan labeled `crypto_erase` **refuses to overwrite** unless you pass `--method overwrite` — the action always matches
  the label, so nothing is deleted under a mislabeled plan.
- Free-space reports `performed=False` (not a false success) when nothing was written; the destructive primitives refuse
  to run unless called through the gated engine.

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
