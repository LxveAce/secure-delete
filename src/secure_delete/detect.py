"""Read-only detection of media (HDD vs SSD/flash) + filesystem for a path.

NEVER writes to the target. On anything uncertain, returns Media.UNKNOWN so the engine
picks the most conservative (never-overclaim) path.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field

from .result import Media

_COW_FS = {"btrfs", "zfs", "apfs", "refs"}


@dataclass
class TargetInfo:
    path: str
    device: str = ""
    media: Media = Media.UNKNOWN
    filesystem: str = ""
    cow: bool = False
    notes: list[str] = field(default_factory=list)


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _probe_linux(path: str) -> TargetInfo:
    info = TargetInfo(path=path)
    info.device = _run(["findmnt", "-no", "SOURCE", "--target", path])
    info.filesystem = _run(["findmnt", "-no", "FSTYPE", "--target", path])
    info.cow = info.filesystem.lower() in _COW_FS
    # rotational flag via lsblk: 1 = magnetic HDD, 0 = SSD/flash (handles nvme/partition mapping)
    rota = _run(["lsblk", "-ndo", "ROTA", info.device]) if info.device else ""
    rota = (rota.splitlines() or [""])[0].strip()
    if rota == "1":
        info.media = Media.HDD
    elif rota == "0":
        info.media = Media.SSD_FLASH
    else:
        info.notes.append("could not determine media (lsblk ROTA unavailable) — treating as UNKNOWN")
    return info


def _run_ps(script: str) -> str:
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip()
    except Exception:
        return ""


def _probe_windows(path: str) -> TargetInfo:
    info = TargetInfo(path=path)
    # READ-ONLY: path -> drive letter -> volume FileSystem + physical-disk MediaType. All Get-* (no writes).
    p = path.replace("'", "''")  # single-quote escape for the PS literal
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$p='{p}';"
        "$dl=(Get-Item -LiteralPath $p).PSDrive.Name;"
        "$fs=(Get-Volume -DriveLetter $dl).FileSystemType;"
        "$dn=(Get-Partition -DriveLetter $dl).DiskNumber;"
        "$mt=(Get-Disk -Number $dn | Get-PhysicalDisk).MediaType;"
        "Write-Output ('MEDIA=' + $mt); Write-Output ('FS=' + $fs); Write-Output ('DEV=Disk' + $dn)"
    )
    media_s = fs_s = ""
    for line in _run_ps(script).splitlines():
        line = line.strip()
        if line.startswith("MEDIA="):
            media_s = line[6:].strip()
        elif line.startswith("FS="):
            fs_s = line[3:].strip()
        elif line.startswith("DEV="):
            info.device = line[4:].strip()
    info.filesystem = fs_s
    info.cow = fs_s.lower() in _COW_FS
    m = media_s.lower()
    if m == "hdd":
        info.media = Media.HDD
    elif m == "ssd":
        info.media = Media.SSD_FLASH
    elif media_s:
        # Unspecified / SCM (USB, VM, virtual, storage-class memory) -> conservative UNKNOWN
        info.notes.append(f"physical-disk MediaType={media_s!r} — treating as UNKNOWN (conservative).")
    else:
        info.notes.append("could not read physical-disk MediaType (PowerShell) — treating as UNKNOWN.")
    return info


def probe(path: str) -> TargetInfo:
    """Read-only: determine media + filesystem for `path`."""
    path = os.path.abspath(path)
    if sys.platform.startswith("linux"):
        return _probe_linux(path)
    if sys.platform.startswith("win"):
        return _probe_windows(path)
    info = TargetInfo(path=path)
    info.notes.append(f"detection not implemented for platform {sys.platform!r} — treating as UNKNOWN")
    return info
