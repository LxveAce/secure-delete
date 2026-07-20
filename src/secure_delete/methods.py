"""Erase methods — GUARDED STUBS. No destruction is implemented in the scaffold.

Each method documents the proven OS tool it will orchestrate, then refuses. Wiring real
destruction is a reviewed + owner-gated step (see SAFETY.md) — deliberately not done here.
"""
from __future__ import annotations

from .detect import TargetInfo
from .result import ScopedResult


class DestructionNotEnabled(NotImplementedError):
    """Raised by every erase method in the scaffold. Destruction is intentionally not implemented."""


def _guard(name: str, tool: str) -> ScopedResult:
    raise DestructionNotEnabled(
        f"{name}: destruction is not implemented in the scaffold (SAFE-by-default). "
        f"When built, this orchestrates `{tool}` behind an explicit confirm gate. See SAFETY.md."
    )


def overwrite_file(info: TargetInfo, passes: int = 1) -> ScopedResult:
    # Windows: sdelete / cipher; Linux: shred (after an FS-caveat check). HDD only for a real 'unrecoverable' claim.
    return _guard("overwrite_file", "sdelete (Win) / shred (Linux)")


def crypto_erase(info: TargetInfo) -> ScopedResult:
    # The robust, media-independent path: destroy the key of an encrypted container/volume.
    return _guard("crypto_erase", "cryptsetup luksErase / manage-bde / VeraCrypt")


def freespace_wipe(info: TargetInfo) -> ScopedResult:
    return _guard("freespace_wipe", "sdelete -z (Win) / sfill (Linux)")


def whole_drive_sanitize(info: TargetInfo) -> ScopedResult:
    return _guard("whole_drive_sanitize", "hdparm --security-erase / nvme sanitize / nvme format --ses")
