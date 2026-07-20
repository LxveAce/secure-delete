"""CLI for Secure Delete. Dry-run by DEFAULT. `--execute` requires an exact typed confirmation.

Own / authorized data only. Whole-drive operations are advisory (they print the command).
"""
from __future__ import annotations

import argparse
import sys

from . import engine, guards
from .detect import probe
from .result import Method


def _confirm_value(token: str, args):
    """The confirmation: --confirm on the CLI, else an interactive prompt. None if neither (gate will refuse)."""
    if getattr(args, "confirm", None) is not None:
        return args.confirm
    if not sys.stdin.isatty():
        return None  # non-interactive + no --confirm -> fails the gate on purpose (safe)
    try:
        return input(f"Type the full path to PERMANENTLY erase it:\n  {token}\n> ").strip()
    except (EOFError, KeyboardInterrupt):
        return None


def _cmd_detect(args) -> int:
    d = probe(args.path)
    print(f"target: {d.path}")
    print(f"  device: {d.device or '(n/a)'}")
    print(f"  media:  {d.media.value}")
    print(f"  fs:     {d.filesystem or '(unknown)'}  cow={d.cow}")
    for n in d.notes:
        print(f"  ! {n}")
    return 0


def _cmd_file(args) -> int:
    plan = engine.plan(args.path, method=args.method)
    print(plan.summary())
    if not args.execute:
        return 0
    try:
        rp = guards.check_file_target(args.path)
    except guards.UnsafeTarget as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2
    if plan.method is not Method.OVERWRITE:  # surface the best-effort refusal BEFORE prompting
        print(f"\nREFUSED: per-file overwrite is best-effort on this target (recommended: {plan.method.value}). "
              "Re-run with `--method overwrite` to force a best-effort overwrite+delete, or use full-disk encryption.",
              file=sys.stderr)
        return 2
    confirm = _confirm_value(guards.confirmation_token(rp), args)
    try:
        res = engine.execute(plan, confirm=confirm, passes=args.passes)
    except guards.BestEffortRefused as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2
    except guards.ConfirmationRequired:
        print("\nABORTED: confirmation did not match — nothing was erased.", file=sys.stderr)
        return 3
    except guards.UnsafeTarget as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"\nERROR: could not erase ({e}) — the file may be locked or in use. Nothing guaranteed erased.", file=sys.stderr)
        return 4
    print("\n" + res.summary())
    return 0


def _cmd_freespace(args) -> int:
    plan = engine.plan_freespace(args.dir)
    print(plan.summary())
    if not args.execute:
        return 0
    try:
        rp = guards.check_dir_target(args.dir)
    except guards.UnsafeTarget as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2
    confirm = _confirm_value(guards.confirmation_token(rp), args)
    margin = int(args.margin * (1 << 30)) if args.margin is not None else None
    maxb = int(args.max * (1 << 30)) if args.max is not None else None
    try:
        res = engine.execute_freespace(args.dir, confirm=confirm, margin_bytes=margin,
                                       max_bytes=maxb, allow_system=args.allow_system_volume)
    except guards.ConfirmationRequired:
        print("\nABORTED: confirmation did not match — nothing was written.", file=sys.stderr)
        return 3
    except guards.UnsafeTarget as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"\nERROR: free-space wipe failed ({e}).", file=sys.stderr)
        return 4
    print("\n" + res.summary())
    return 0


def _cmd_sanitize(args) -> int:
    print(engine.advise_sanitize(args.path).summary())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secure-delete",
        description="Honest secure deletion (crypto-erase first). Dry-run by default; --execute needs an exact typed confirmation.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect", help="(read-only) show detected media + filesystem for a path")
    d.add_argument("path")
    d.set_defaults(func=_cmd_detect)

    f = sub.add_parser("file", help="securely erase a file (dry-run unless --execute)")
    f.add_argument("path")
    f.add_argument("--method", default="auto", choices=["auto", "overwrite"],
                   help="auto routes by media (crypto-erase recommended on SSD); the file is always overwritten+deleted")
    f.add_argument("--execute", action="store_true", help="actually erase (requires a typed confirmation)")
    f.add_argument("--confirm", metavar="PATH", help="non-interactive confirmation: must equal the resolved target path")
    f.add_argument("--passes", type=int, default=1, help="overwrite passes (1 is enough on modern drives)")
    f.set_defaults(func=_cmd_file)

    fs = sub.add_parser("freespace", help="wipe unallocated space on a volume (dry-run unless --execute)")
    fs.add_argument("dir", help="any directory on the target volume")
    fs.add_argument("--execute", action="store_true")
    fs.add_argument("--confirm", metavar="PATH", help="non-interactive confirmation: must equal the resolved directory path")
    fs.add_argument("--margin", type=float, metavar="GiB", help="min free space to leave (default: max(1 GiB, 10%% of volume))")
    fs.add_argument("--max", type=float, metavar="GiB", help="cap how much fill to write")
    fs.add_argument("--allow-system-volume", action="store_true", help="permit wiping free space on the system/boot volume")
    fs.set_defaults(func=_cmd_freespace)

    s = sub.add_parser("sanitize", help="(advisory) print the whole-drive secure-erase command for a path's drive")
    s.add_argument("path")
    s.set_defaults(func=_cmd_sanitize)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
