"""CLI for secure-delete. Dry-run is the DEFAULT; --execute refuses (gated). Destroys nothing."""
from __future__ import annotations

import argparse
import sys

from . import detect, engine


def _cmd_detect(args) -> int:
    info = detect.probe(args.path)
    print(f"target: {info.path}")
    print(f"  device: {info.device or '(n/a)'}")
    print(f"  media:  {info.media.value}")
    print(f"  fs:     {info.filesystem or '(unknown)'}  cow={info.cow}")
    for n in info.notes:
        print(f"  ! {n}")
    return 0


def _cmd_file(args) -> int:
    res = engine.plan(args.path, method=args.method)
    print(res.summary())
    if args.execute:
        print(
            "\n--execute is gated: destruction is not implemented in the scaffold (SAFE-by-default). See SAFETY.md.",
            file=sys.stderr,
        )
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secure-delete",
        description="Secure-deletion primitive (SCAFFOLD). Dry-run by default; destroys nothing.",
    )
    p.add_argument("--execute", action="store_true", help="(gated) attempt real erase — refuses in the scaffold")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("detect", help="(read-only) show detected media + filesystem for a path")
    d.add_argument("path")
    d.set_defaults(func=_cmd_detect)
    f = sub.add_parser("file", help="plan an honest secure-erase for a file path")
    f.add_argument("path")
    f.add_argument(
        "--method",
        default="auto",
        choices=["auto", "overwrite", "crypto_erase", "freespace_wipe", "whole_drive_sanitize"],
    )
    f.set_defaults(func=_cmd_file)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
