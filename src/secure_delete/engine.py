"""Orchestrator: detect -> choose the honest method -> plan (dry-run) / execute (guarded, gated).

plan() is read-only and safe. Every destructive path (execute, execute_freespace) runs the
guard checks AND the exact-match confirmation gate BEFORE touching anything, and refuses to
overwrite when the honest method is not `overwrite` (so a crypto-erase plan never silently deletes).
"""
from __future__ import annotations

import shutil

from . import guards, methods
from .detect import TargetInfo, probe
from .result import Media, Method, ScopedResult, build_claim, residuals_for

_GiB = 1 << 30


def choose_method(info: TargetInfo, requested: str = "auto") -> Method:
    if requested != "auto":
        return Method(requested)
    # auto = honest routing: overwrite is only trustworthy on a magnetic HDD with an in-place FS.
    if info.media is Media.HDD and not info.cow:
        return Method.OVERWRITE
    # SSD, copy-on-write, or unknown media -> crypto-erase is the honest robust recommendation.
    return Method.CRYPTO_ERASE


def plan(path: str, method: str = "auto") -> ScopedResult:
    """DRY-RUN: describe the honest erase plan for `path`. Reads only; destroys nothing."""
    info = probe(path)
    m = choose_method(info, method)
    res = ScopedResult(
        target=info.path, media=info.media, filesystem=info.filesystem or "unknown",
        method=m, performed=False,
        claim=build_claim(info.media, m),
        residuals=residuals_for(info.media, info.filesystem, info.cow),
        warnings=list(info.notes),
    )
    if m is not Method.OVERWRITE:
        res.warnings.append(
            "this target is best-effort for per-file overwrite (flash/CoW/unknown). `file --execute` will REFUSE "
            "unless you pass `--method overwrite` to force a best-effort overwrite+delete; for a real guarantee use "
            "full-disk encryption. (`secure-delete sanitize` prints the whole-drive command.)"
        )
    return res


def execute(plan_result: ScopedResult, confirm: str | None = None, passes: int = 1) -> ScopedResult:
    """Perform a per-file secure erase. GUARD -> best-effort refusal -> exact-match CONFIRMATION -> overwrite+delete.

    Refuses unless the plan's method is OVERWRITE, so the action always matches the label (no crypto-erase plan
    silently deletes). Force a best-effort overwrite on flash/CoW by planning with method='overwrite'."""
    rp = guards.check_file_target(plan_result.target)
    if plan_result.method is not Method.OVERWRITE:
        raise guards.BestEffortRefused(
            f"per-file overwrite of this target is best-effort (recommended: {plan_result.method.value}). "
            "Re-run with `--method overwrite` to force a best-effort overwrite+delete, or use full-disk encryption "
            "(and `secure-delete sanitize` for the whole-drive command)."
        )
    guards.require_confirmation(rp, confirm)
    info = probe(str(rp))  # fresh read-only re-probe after the gate
    return methods.overwrite_file(rp, info, passes, _internal=True)


def plan_freespace(work_dir: str) -> ScopedResult:
    info = probe(work_dir)
    warn = ["dry-run: --execute fills unallocated space with random data (leaving a safety margin), then removes it."]
    if guards.is_system_volume(work_dir):
        warn.append("NOTE: this is the SYSTEM/boot volume — --execute will REFUSE unless you pass --allow-system-volume.")
    return ScopedResult(
        target=info.path, media=info.media, filesystem=info.filesystem or "unknown",
        method=Method.FREESPACE_WIPE, performed=False,
        claim=build_claim(info.media, Method.FREESPACE_WIPE),
        residuals=residuals_for(info.media, info.filesystem, info.cow),
        warnings=warn,
    )


def execute_freespace(work_dir: str, confirm: str | None = None, margin_bytes: int | None = None,
                      max_bytes: int | None = None, allow_system: bool = False) -> ScopedResult:
    """Wipe unallocated space on `work_dir`'s volume. GUARD + CONFIRMATION + system-volume policy before writing.

    Enforces a dynamic safety margin (>= max(1 GiB, 10% of volume)) and refuses the system/boot volume unless
    `allow_system` is set."""
    rp = guards.check_dir_target(work_dir)
    guards.require_confirmation(rp, confirm)
    info = probe(str(rp))
    total = shutil.disk_usage(str(rp)).total
    dyn_margin = max(_GiB, int(total * 0.10))
    margin = dyn_margin if margin_bytes is None else max(margin_bytes, 0)
    if guards.is_system_volume(str(rp)):
        if not allow_system:
            raise guards.UnsafeTarget(
                "refusing to wipe free space on the SYSTEM/boot volume — filling it can break the OS mid-run. "
                "Re-run with --allow-system-volume if you accept the risk (a large safety margin is still enforced)."
            )
        margin = max(margin, dyn_margin)  # never below the dynamic margin on the system volume
    return methods.freespace_wipe(info, rp, margin_bytes=margin, max_bytes=max_bytes, _internal=True)


def advise_sanitize(path: str) -> ScopedResult:
    """ADVISORY: return the whole-drive sanitize command for the drive holding `path`. Runs nothing."""
    return methods.whole_drive_sanitize_advice(probe(path))


def advise_crypto(path: str) -> ScopedResult:
    """ADVISORY: return the crypto-erase command for the volume holding `path`. Runs nothing."""
    return methods.crypto_erase_advice(probe(path))
