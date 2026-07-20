"""Orchestrator: detect -> choose the honest method -> build a ScopedResult plan (dry-run).

plan() is read-only and safe. execute() is guarded and refuses in the scaffold.
"""
from __future__ import annotations

from . import methods
from .detect import TargetInfo, probe
from .result import Media, Method, ScopedResult, build_claim, residuals_for


def choose_method(info: TargetInfo, requested: str = "auto") -> Method:
    if requested != "auto":
        return Method(requested)
    # auto = honest routing: overwrite is only trustworthy on a magnetic HDD with an in-place FS.
    if info.media is Media.HDD and not info.cow:
        return Method.OVERWRITE
    # SSD, copy-on-write, or unknown media -> crypto-erase is the honest robust choice.
    return Method.CRYPTO_ERASE


def plan(path: str, method: str = "auto") -> ScopedResult:
    """DRY-RUN: describe the honest erase plan for `path`. Reads only; destroys nothing."""
    info = probe(path)
    m = choose_method(info, method)
    res = ScopedResult(
        target=info.path,
        media=info.media,
        filesystem=info.filesystem or "unknown",
        method=m,
        performed=False,
        claim=build_claim(info.media, m),
        residuals=residuals_for(info.media, info.filesystem, info.cow),
        warnings=list(info.notes),
    )
    if info.media in (Media.SSD_FLASH, Media.UNKNOWN) and m is Method.OVERWRITE:
        res.warnings.append(
            "overwrite requested on flash/unknown media — cannot guarantee unrecoverability; prefer crypto-erase."
        )
    return res


def execute(plan_result: ScopedResult, confirm_token: str | None = None) -> ScopedResult:
    """GATED: perform the erase. Not implemented in the scaffold — always refuses."""
    raise methods.DestructionNotEnabled(
        "execute() is disabled in the scaffold. Real execution requires the reviewed + owner-gated "
        "implementation of methods.py plus an explicit confirm gate. See SAFETY.md / PLAN.md (P1)."
    )
