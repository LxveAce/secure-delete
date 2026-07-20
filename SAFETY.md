# Safety

This tool destroys data on purpose. It's built to be careful about it. Here's how it behaves and where its guarantees stop.

## Current behavior (v0.3, Rust)
- Dry-run by default. `overwrite` does nothing without `--execute` and a matching `--confirm`, and it refuses symlinks and anything that isn't a regular file.
- The vault destroys the key, not the bytes. `shred` drops a file's key and re-keys the vault. On a plain software vault (no special hardware) one gap remains: an old wrapped key could still be sitting in unaddressable flash, and recovering a shredded file would take both that exact NAND slot and the passphrase. That's much harder than pulling back a plaintext file, but it isn't a hardware-guaranteed zero. Changing the passphrase with `rekey` closes it in software.
- `init --tpm` closes that gap in hardware. The master key is wrapped under `HKDF(RWK ‖ KEK)`, where the RWK is sealed by the TPM, so opening the vault needs both the hardware and the passphrase. `hardware-shred` destroys the TPM key, after which a stale wrapped key left in flash can't be opened even with the passphrase. How strong that is depends on the platform:
  - Windows (Platform Crypto Provider): the TPM key is an SRK-wrapped `.PCPKEY` blob stored on disk that only this machine's TPM can use. Deleting it stops anyone who only has a flash image and the passphrase, but it's defense in depth, not a wipe inside the chip.
  - Linux (tpm2-tools): the RWK is sealed into a persisted, evictable object inside the TPM and is never wrapped on disk (the transient blobs stay in `/dev/shm`). Evicting it is a real in-hardware erase. This is the stronger case.
  - macOS Secure Enclave is designed but not built.

  A tampered header can't quietly downgrade a TPM vault to software, because the master seal binds the root descriptor as AEAD associated data. A one-time recovery code is minted by default (skip it with `--i-understand-total-loss`) and survives TPM loss. Guard that code like the data itself: the code, the vault folder, and the passphrase together reopen the vault.
- A TPM vault is tied to one machine. A TPM clear, firmware reset, or hardware swap makes it unopenable except through the recovery code, so copying the vault folder is not a backup. `vault-status` reports the real state (reachable, key gone, or TPM unreachable) and never prints a bare "unrecoverable".
- Keys are held in zeroized buffers and never hit the disk in the clear. Crypto is RustCrypto (AES-256-GCM, Argon2id, HKDF-SHA256). One thing the tool does not claim to scrub: while a file is open, its plaintext and the unsealed master key sit in RAM, which the OS can page out to the pagefile or hiberfil. For a high-value vault, encrypt the pagefile (`fsutil behavior set encryptpagingfile 1`) and turn off hibernation. The shred guarantee only covers data that was never decrypted into RAM on this machine.
- Your own or authorized data only. No telemetry, works offline.

## Design posture, carried over from v0.1 (Python, `v0.1.0`)
- Destruction is real but gated. Per-file overwrite and free-space wipe are implemented, but they only run through `engine.execute` / `engine.execute_freespace`, each of which first runs the guard checks (refuse system paths, symlinks, non-files) and an exact-match confirmation (the caller has to supply the resolved target path).
- Dry-run is the default. `engine.plan()` and the CLI without `--execute` only describe what would happen. `--execute` prompts you to type the exact path, or takes `--confirm <path>` for scripts.
- Whole-drive operations are advisory. `crypto_erase_advice` and `whole_drive_sanitize_advice` return the OS command and run nothing themselves.
- Detection is read-only. It reads `/sys`, `findmnt`/`lsblk`, or `Get-*` cmdlets, and never writes to the target.

## Red-team hardening (2026-07-20)
An adversarial review turned up these problems, all now fixed and covered by tests:
- The protected-root check treated `/` as an ancestor, which refused every file on Linux; that's gone, and it now also refuses files sitting directly in a volume or drive root (like `C:\bootmgr`). `SystemRoot` falls back to `C:\Windows`.
- Free-space wipe refuses the system or boot volume unless you pass `--allow-system-volume`, always keeps a margin of at least max(1 GiB, 10% of the volume), writes one growable fill file, verifies it cleaned up, and warns loudly if anything is left over.
- Per-file overwrite opens a validated descriptor with `O_NOFOLLOW` and re-checks it's a regular file, which closes the check-then-open race (TOCTOU).
- A plan labeled `crypto_erase` refuses to overwrite unless you pass `--method overwrite`, so the action always matches the label and nothing gets deleted under a mislabeled plan.
- Free-space reports `performed=False` when nothing was written instead of a false success, and the destructive primitives refuse to run unless they're called through the gated engine.

## Rules for the gated destructive paths
1. Your own or authorized data only. This is privacy tooling in the `shred` / `sdelete` / BleachBit / VeraCrypt tradition, for protecting data you own, not for evading lawful process or destroying someone else's data.
2. Scope every claim. Never say a plain "unrecoverable." On SSD, flash, and copy-on-write filesystems, a file overwrite is best-effort, so say that. Crypto-erase is the reliable guarantee; prefer it.
3. Confirm and double-gate. Real execution has to require an explicit target confirmation, default to doing nothing, check the target is what the user meant (not a system or mounted-in-use path), and back up or refuse when it's ambiguous. No silent or automatic destruction.
4. Lean on proven tools (sdelete, cipher, shred, blkdiscard, hdparm, nvme, cryptsetup) instead of hand-rolling raw disk overwrite; they already handle the resident-file and firmware-sanitize edge cases.
5. Verify, don't trust. Firmware sanitize commands have known bugs (FAST'11), so check that the erase actually happened rather than assuming it did.
6. Dead Man's Switch integration is separate and gated. Any change to a destruct path goes through the Operating-Rules irreversibility gate: ready the patch, get owner sign-off, validate on a designated spare board, then commit. Never auto-push.
7. No PII or secrets in commits. LxveAce identity, human voice.

## The self-cleaning uninstaller (design only, for now)
The overwrite-on-uninstall idea (a detached helper that outlives the app, then erases and removes the app's files including itself) is sketched out in the vault design-log. It isn't implemented here, and the concrete self-deleting helper is an authorization-gated detail. An earlier automated research pass on it tripped a cyber-safeguard, logged in `command-center/SAFEGUARDS-LOG.md` on 2026-07-18.
