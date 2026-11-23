"""Command-line interface for leafproof's verification harness."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .harness import run
from .report import write_report

EXIT_OK = 0
EXIT_ERROR = 2


def cmd_run(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    result = run(workdir, count=args.leaves, tamper_samples=args.tamper, seed=args.seed)
    report = write_report(result, workdir / "reports")
    print(f"leafproof {__version__}  {result['leaves']} leaves  height {result['height']}")
    print(f"root matches Python: {result['root_matches']}  levels match: {result['levels_match']}")
    print(f"proofs verified: {result['proofs_verified']}/{result['proofs']}")
    print(
        f"tamper rejected: leaves {result['rejected_tampered_leaves']}/"
        f"{result['tampered_leaves']}, paths {result['rejected_tampered_paths']}/"
        f"{result['tampered_paths']}"
    )
    print(f"report: {report}")
    ok = (
        result["root_matches"]
        and result["levels_match"]
        and result["proofs_verified"] == result["proofs"]
        and result["rejected_tampered_leaves"] == result["tampered_leaves"]
        and result["rejected_tampered_paths"] == result["tampered_paths"]
    )
    return EXIT_OK if ok else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leafproof", description="Verify Merkle inclusion proofs independently."
    )
    parser.add_argument("--version", action="version", version=f"leafproof {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_cmd = subparsers.add_parser("run", help="build a tree, prove, verify, and tamper")
    run_cmd.add_argument("--leaves", type=int, default=5000)
    run_cmd.add_argument("--tamper", type=int, default=200)
    run_cmd.add_argument("--seed", type=int, default=41)
    run_cmd.add_argument("--workdir", default="leafproof-run")
    run_cmd.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, OSError) as error:
        print(f"leafproof: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
