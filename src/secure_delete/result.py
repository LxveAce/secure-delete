"""The honest-claim contract for secure-delete.

A ScopedResult describes EXACTLY what an erase operation did (or, in dry-run, would do),
scoped to the detected media + filesystem. Cardinal rule: never emit an unqualified
"unrecoverable" — state what was overwritten and what residual copies may survive.
Pure logic, no side effects — safe and fully unit-testable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Media(str, Enum):
    HDD = "hdd"          # magnetic — in-place overwrite is reliable
    SSD_FLASH = "ssd"    # NAND flash (SSD/NVMe/eMMC/UFS/SD/USB) — overwrite is UNRELIABLE
    UNKNOWN = "unknown"  # treat as the most conservative case (never overclaim)


class Method(str, Enum):
    OVERWRITE = "overwrite"
    CRYPTO_ERASE = "crypto_erase"
    FREESPACE_WIPE = "freespace_wipe"
    WHOLE_DRIVE_SANITIZE = "whole_drive_sanitize"
    NONE = "none"


@dataclass
class ScopedResult:
    target: str
    media: Media
    filesystem: str
    method: Method
    performed: bool = False  # False in dry-run / scaffold
    claim: str = ""          # honest + scoped — set via build_claim()
    residuals: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        head = "DID" if self.performed else "PLAN (dry-run — nothing was destroyed)"
        lines = [
            f"[{head}] target={self.target}",
            f"  media={self.media.value}  fs={self.filesystem}  method={self.method.value}",
            f"  claim: {self.claim}",
        ]
        lines += [f"  residual: {r}" for r in self.residuals]
        lines += [f"  ! {w}" for w in self.warnings]
        return "\n".join(lines)


# --- honest claim / residual builders (the honesty spine) ---

def build_claim(media: Media, method: Method) -> str:
    """A scoped, honest claim string — NEVER an unqualified 'unrecoverable'."""
    if method is Method.CRYPTO_ERASE:
        return ("crypto-erase — if the data was encrypted at rest, destroying the key makes every remaining copy "
                "(including SSD spare/over-provisioned NAND) unrecoverable. Only as strong as: the data was ciphertext "
                "from first write AND the key is truly gone.")
    if method is Method.OVERWRITE:
        if media is Media.HDD:
            return "overwrote this file's currently-allocated blocks; software/lab recovery of them is infeasible (HDD)."
        return ("best-effort overwrite only — on flash/SSD the controller may relocate the write, so the original can "
                "survive in un-erased NAND. NOT a guarantee. Prefer crypto-erase for unrecoverability.")
    if method is Method.FREESPACE_WIPE:
        return "overwrote currently-unallocated space (previously-deleted file data). Does NOT reach filenames in directory slack."
    if method is Method.WHOLE_DRIVE_SANITIZE:
        return "issued a controller-level whole-drive sanitize / secure-erase — verify success; firmware bugs exist (FAST'11)."
    return "no erase performed."


def residuals_for(media: Media, filesystem: str, cow: bool) -> list[str]:
    out: list[str] = []
    if media in (Media.SSD_FLASH, Media.UNKNOWN):
        out.append("SSD spare / over-provisioned NAND is unaddressable by software — stale copies may persist until garbage collection.")
    if cow:
        out.append("copy-on-write / snapshot filesystem: old blocks are retained and may be pinned by snapshots — delete snapshots or crypto-erase.")
    if "ntfs" in (filesystem or "").lower():
        out.append("NTFS: $LogFile/$UsnJrnl, VSS shadow copies, and MFT-resident small-file remnants may survive — run a free-space + MFT cleanse.")
    out.append("OS side-channels a single-file wipe never touches: pagefile/hiberfil, temp files, app/thumbnail caches.")
    return out
