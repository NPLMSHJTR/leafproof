"""Markdown report for leafproof."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def write_report(result: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# leafproof report",
        "",
        f"- leaves: {result['leaves']}",
        f"- tree height: {result['height']}",
        f"- audit path length: {result['path_length']} hashes (log2 of leaf count)",
        f"- root: `{result['root']}`",
        "",
        "## Independent reconstruction",
        "",
        "| check | result |",
        "| --- | --- |",
        f"| Python root equals TypeScript root | {'yes' if result['root_matches'] else 'NO'} |",
        f"| every level matches | {'yes' if result['levels_match'] else 'NO'} |",
        f"| inclusion proofs verified | {result['proofs_verified']}/{result['proofs']} |",
        "",
        "## Tamper rejection",
        "",
        "| attack | rejected |",
        "| --- | --- |",
        f"| forged leaf, original path | {result['rejected_tampered_leaves']}/{result['tampered_leaves']} |",
        f"| altered sibling hash | {result['rejected_tampered_paths']}/{result['tampered_paths']} |",
        "",
        "A proof is only useful if it fails for the right reasons. Both attacks "
        "keep the proof structurally valid — right length, right shape — and are "
        "rejected purely by the hash chain.",
    ]
    path = out_dir / "report.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path
