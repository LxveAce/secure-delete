"""Safety guards for real erasure — refuse anything that isn't clearly a user data file.

These run BEFORE any destructive operation (see engine.execute*). Own/authorized data only.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


class UnsafeTarget(Exception):
    """The target is not something we will erase (system path, non-file, symlink, missing…)."""


class ConfirmationRequired(Exception):
    """execute() was called without a confirmation that matches the exact target."""


class BestEffortRefused(Exception):
    """Per-file overwrite was refused because on this media it can only be best-effort (SSD/CoW)."""


def _protected_roots() -> list[Path]:
    """Specific OS/program directories we refuse to erase from. NOTE: volume roots ('/', 'C:\\') are handled
    separately via `_is_volume_root` — they are intentionally NOT in this list (an ancestor '/' would match
    every path and break the whole tool on Linux)."""
    roots: list[Path] = []
    if sys.platform.startswith("win"):
        sysroot = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
        roots.append(Path(sysroot))
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            v = os.environ.get(env)
            if v:
                roots.append(Path(v))
    else:
        roots += [Path(p) for p in (
            "/bin", "/sbin", "/usr", "/etc", "/boot", "/lib", "/lib64",
            "/sys", "/proc", "/dev", "/run", "/var",
        )]
    out: list[Path] = []
    for r in roots:
        try:
            out.append(r.resolve())
        except OSError:
            out.append(r)
    return out


def _is_volume_root(p: Path) -> bool:
    """True if `p` is a filesystem/drive root ('/' on POSIX, 'C:\\' on Windows)."""
    return p == p.parent


def _under_protected_root(rp: Path) -> Path | None:
    for root in _protected_roots():
        if rp == root or root in rp.parents:
            return root
    return None


def is_system_volume(path: str) -> bool:
    """True if `path` lives on the OS/boot volume. Conservative: unknown -> True."""
    try:
        p = Path(path).resolve()
    except OSError:
        return True
    if sys.platform.startswith("win"):
        sysdrive = (os.environ.get("SystemDrive") or "C:").rstrip("\\")
        return (p.drive or "").upper() == sysdrive.upper()
    try:
        return os.stat(p).st_dev == os.stat("/").st_dev
    except OSError:
        return True


def check_file_target(path: str) -> Path:
    """Return a resolved Path if `path` is a safe, ordinary user file to erase; else raise UnsafeTarget."""
    p = Path(path)
    if p.is_symlink():
        raise UnsafeTarget("target is a symlink — refusing (erasing it would follow to the link's target)")
    try:
        rp = p.resolve()
    except OSError as e:
        raise UnsafeTarget(f"cannot resolve path: {e}")
    if not rp.exists():
        raise UnsafeTarget("target does not exist")
    if not rp.is_file():
        raise UnsafeTarget("target is not a regular file (directory / device / special) — refusing")
    if _is_volume_root(rp.parent):
        raise UnsafeTarget(f"target sits directly in a volume/drive root ({rp.parent}) — refusing (boot/system files live there)")
    root = _under_protected_root(rp)
    if root is not None:
        raise UnsafeTarget(f"target is under a protected system directory ({root}) — refusing")
    return rp


def check_dir_target(path: str) -> Path:
    """Return a resolved Path if `path` is a safe directory to run a free-space wipe in; else raise UnsafeTarget."""
    p = Path(path)
    if p.is_symlink():
        raise UnsafeTarget("target is a symlink — refusing")
    try:
        rp = p.resolve()
    except OSError as e:
        raise UnsafeTarget(f"cannot resolve path: {e}")
    if not rp.exists() or not rp.is_dir():
        raise UnsafeTarget("target is not an existing directory")
    if _is_volume_root(rp):
        raise UnsafeTarget(f"target is a volume/drive root ({rp}) — pick a sub-directory on the volume instead")
    root = _under_protected_root(rp)
    if root is not None and rp != root:
        raise UnsafeTarget(f"target is under a protected system directory ({root}) — refusing")
    return rp


def confirmation_token(rp: Path) -> str:
    """The exact string a caller must supply to confirm destruction of `rp`."""
    return str(rp)


def require_confirmation(rp: Path, confirm: str | None) -> None:
    """Raise unless `confirm` exactly matches the target's confirmation token."""
    if confirm is None or confirm.strip() != confirmation_token(rp):
        raise ConfirmationRequired(
            "destruction requires an exact confirmation equal to the resolved target path "
            f"({confirmation_token(rp)!r}); got {confirm!r}."
        )
