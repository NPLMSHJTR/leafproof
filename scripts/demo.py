#!/usr/bin/env python3
"""Run leafproof end to end: build, prove, verify, and tamper."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if shutil.which("node") is None:
        print("node is required", file=sys.stderr)
        return 2
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "python" / "src")
    command = [sys.executable, "-m", "leafproof", "run", "--workdir", "leafproof-run"]
    print("$ " + " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True, env=env)
    print()
    print(f"report: {ROOT / 'leafproof-run' / 'reports' / 'report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
