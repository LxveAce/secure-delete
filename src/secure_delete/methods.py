"""Erase methods. Reached ONLY via engine.execute*() (guards + confirmation gate); the
`_internal` flag enforces that even for direct importers. Own / authorized data only.

Per-file overwrite and free-space wipe are REAL. Whole-drive crypto-erase / sanitize are
ADVISORY — they return the exact OS command rather than wrapping an irreversible drive wipe.
"""
from __future__ import annotations

import os
import shutil
import stat as _stat
from pathlib import Path

from .detect import TargetInfo
from .guards import UnsafeTarget
from .result import Media, Method, ScopedResult, build_claim, residuals_for

_CHUNK = 1 << 20        # 1 MiB write unit
_STEP = 64 * _CHUNK     # 64 MiB per free-space step
_NOT_INTERNAL = "must be called via engine.execute*() (guards + confirmation) — not directly."


def _make_writable(path: str) -> None:
    try:
        os.chmod(path, _stat.S_IWRITE | _stat.S_IREAD)
    except OSError:
        pass


def _open_regular_rw(path: str) -> tuple[int, int]:
    """Open `path` for read/write WITHOUT following a symlink, verify it's a regular file, return (fd, size).
    Opening the validated inode directly closes the check->open swap window (TOCTOU)."""
    flags = os.O_RDWR
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    st = os.fstat(fd)
    if not _stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise UnsafeTarget("target is not a regular file at open time — refusing")
    return fd, st.st_size


def overwrite_file(rp: Path, info: TargetInfo, passes: int = 1, *, _internal: bool = False) -> ScopedResult:
    """Overwrite the file's bytes (via a validated fd), obscure its name, then delete it."""
    if not _internal:
        raise RuntimeError("overwrite_file " + _NOT_INTERNAL)
    path = str(rp)
    _make_writable(path)
    fd, length = _open_regular_rw(path)
    try:
        for _ in range(max(1, passes)):
            os.lseek(fd, 0, os.SEEK_SET)
            remaining = length
            while remaining > 0:
                n = _CHUNK if remaining > _CHUNK else remaining
                os.write(fd, os.urandom(n))
                remaining -= n
        os.fsync(fd)
    finally:
        os.close(fd)
    # obscure the directory-entry filename before unlinking (best-effort; may persist in FS metadata)
    target = path
    try:
        obscured = rp.with_name("0" * max(1, len(rp.name)))
        if not obscured.exists():
            os.replace(path, str(obscured))
            target = str(obscured)
    except OSError:
        pass
    os.remove(target)
    warnings: list[str] = []
    if info.media in (Media.SSD_FLASH, Media.UNKNOWN):
        warnings.append(
            "flash/SSD: this overwrite is BEST-EFFORT — the controller may have relocated the data, so the original "
            "can persist in NAND. For guaranteed unrecoverability, use full-disk encryption (BitLocker / LUKS / "
            "FileVault) and destroy the key."
        )
    return ScopedResult(
        target=path, media=info.media, filesystem=info.filesystem or "unknown",
        method=Method.OVERWRITE, performed=True,
        claim=build_claim(info.media, Method.OVERWRITE),
        residuals=residuals_for(info.media, info.filesystem, info.cow),
        warnings=warnings,
    )


def freespace_wipe(info: TargetInfo, work_dir: Path, margin_bytes: int = 1 << 30,
                   max_bytes: int | None = None, *, _internal: bool = False) -> ScopedResult:
    """Overwrite unallocated space on `work_dir`'s volume by filling it with random data (leaving `margin_bytes`
    free), then removing the fill. Reaches previously-deleted file DATA; does NOT reach filenames in directory
    slack, FS journals, snapshots, or SSD spare area. `max_bytes` caps the fill (for testing)."""
    if not _internal:
        raise RuntimeError("freespace_wipe " + _NOT_INTERNAL)
    fill_dir = work_dir / ".secure-delete-freespace-tmp"
    if fill_dir.exists():
        shutil.rmtree(str(fill_dir), ignore_errors=True)
        if fill_dir.exists():
            raise OSError(f"a previous free-space fill dir exists and could not be removed: {fill_dir}")
    fill_dir.mkdir(parents=True, exist_ok=True)
    fill = fill_dir / "fill.bin"
    written = 0
    try:
        with open(fill, "wb", buffering=0) as f:
            while True:
                free = shutil.disk_usage(str(work_dir)).free
                if free <= margin_bytes:
                    break
                if max_bytes is not None and written >= max_bytes:
                    break
                budget = free - margin_bytes
                if max_bytes is not None:
                    budget = min(budget, max_bytes - written)
                step = min(budget, _STEP)
                if step <= 0:
                    break
                f.write(os.urandom(step))
                written += step
            f.flush()
            os.fsync(f.fileno())
    finally:
        shutil.rmtree(str(fill_dir), ignore_errors=True)
        cleanup_ok = not fill_dir.exists()

    performed = written > 0
    warnings: list[str] = []
    if performed:
        warnings.append(f"wrote ~{written >> 20} MiB of random fill, then removed it (left ~{margin_bytes >> 20} MiB free).")
        claim = build_claim(info.media, Method.FREESPACE_WIPE)
    else:
        warnings.append("no unallocated space above the safety margin was available — nothing was written.")
        claim = "no free space wiped (the volume is already at/below the safety margin)."
    if not cleanup_ok:
        warnings.append(f"WARNING: could not fully remove the fill dir {fill_dir} — reclaim that space manually.")
    if performed and info.media in (Media.SSD_FLASH, Media.UNKNOWN):
        warnings.append("flash/SSD: free-space fill is best-effort — the controller decides physical placement.")
    return ScopedResult(
        target=str(work_dir), media=info.media, filesystem=info.filesystem or "unknown",
        method=Method.FREESPACE_WIPE, performed=performed, claim=claim,
        residuals=residuals_for(info.media, info.filesystem, info.cow) if performed else [],
        warnings=warnings,
    )


def crypto_erase_advice(info: TargetInfo) -> ScopedResult:
    """ADVISORY — crypto-erase is a whole-volume key-destruction op, not per-file, and irreversible; not run here."""
    if info.filesystem and "ntfs" in info.filesystem.lower():
        cmd = "BitLocker: re-key the volume (manage-bde) and destroy the old key"
    else:
        cmd = "cryptsetup luksErase <device>  (destroys all LUKS key-slots -> ciphertext unrecoverable)"
    return ScopedResult(
        target=info.path, media=info.media, filesystem=info.filesystem or "unknown",
        method=Method.CRYPTO_ERASE, performed=False,
        claim="ADVISORY: crypto-erase is a whole-volume operation and is not executed by this tool.",
        residuals=[],
        warnings=[f"To crypto-erase, on an encrypted volume run: {cmd}",
                  "Only works if the data was encrypted at rest from first write."],
    )


def whole_drive_sanitize_advice(info: TargetInfo) -> ScopedResult:
    """ADVISORY — whole-drive sanitize destroys the ENTIRE drive; never executed by this tool."""
    dev = info.device or "<device>"
    if info.media is Media.SSD_FLASH:
        cmd = f"nvme sanitize {dev}   (or: nvme format {dev} --ses=1) — then verify with `nvme sanitize-log`"
    else:
        cmd = f"hdparm --security-erase-enhanced <pass> {dev}   (the drive must not be BIOS-frozen)"
    return ScopedResult(
        target=dev, media=info.media, filesystem=info.filesystem or "unknown",
        method=Method.WHOLE_DRIVE_SANITIZE, performed=False,
        claim="ADVISORY: whole-drive sanitize erases the ENTIRE drive and is not executed by this tool.",
        residuals=[],
        warnings=[f"To sanitize the whole drive, run: {cmd}",
                  "This destroys ALL data on the device. Verify success afterward (firmware bugs exist)."],
    )
