"""Independent verifier for leafproof.

The Python tree is written from the RFC 6962 description, not ported from the
TypeScript. If the two disagree, one of them is wrong, and the test says so.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / "src" / "tree.ts"


def leaf_hash(data: bytes) -> str:
    return hashlib.sha256(b"\x00" + data).hexdigest()


def node_hash(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_levels(items: list[bytes]) -> list[list[str]]:
    levels = [[leaf_hash(item) for item in items]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt = []
        for index in range(0, len(current), 2):
            if index + 1 < len(current):
                nxt.append(node_hash(current[index], current[index + 1]))
            else:
                nxt.append(current[index])
        levels.append(nxt)
    return levels


def verify_proof(proof: dict[str, Any]) -> bool:
    current = proof["leaf"]
    for step in proof["path"]:
        current = node_hash(step["hash"], current) if step["left"] else node_hash(current, step["hash"])
    return bool(current == proof["root"])


def run_tool(command: str, **flags: str) -> dict[str, Any]:
    arguments = ["node", "--experimental-strip-types", str(TOOL), command]
    for key, value in flags.items():
        arguments.extend([f"--{key}", value])
    completed = subprocess.run(arguments, capture_output=True, text=True, check=True)
    return {"stdout": completed.stdout.strip()}


def make_items(count: int, seed: int) -> list[bytes]:
    items = []
    for index in range(count):
        payload = f"record-{seed}-{index:06d}-" + ("x" * (index % 17))
        items.append(payload.encode())
    return items


def run(workdir: Path, count: int = 5000, tamper_samples: int = 200, seed: int = 41) -> dict[str, Any]:
    workdir.mkdir(parents=True, exist_ok=True)
    items = make_items(count, seed)
    items_path = workdir / "items.txt"
    items_path.write_text("\n".join(item.decode() for item in items) + "\n", encoding="utf-8", newline="\n")

    tree_path = workdir / "tree.json"
    proofs_path = workdir / "proofs.json"
    build = run_tool("build", input=str(items_path), out=str(tree_path))
    run_tool("prove", tree=str(tree_path), out=str(proofs_path), limit="600")

    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    proofs = json.loads(proofs_path.read_text(encoding="utf-8"))["proofs"]
    levels = build_levels(items)
    python_root = levels[-1][0]

    root_matches = python_root == tree["root"]
    levels_match = levels == tree["levels"]
    verified = sum(1 for proof in proofs if verify_proof(proof))

    # Tamper 1: change the leaf, keep the path. The proof must fail.
    rejected_leaf = 0
    for proof in proofs[:tamper_samples]:
        forged = dict(proof)
        forged["leaf"] = leaf_hash(b"forged-" + str(proof["index"]).encode())
        if not verify_proof(forged):
            rejected_leaf += 1

    # Tamper 2: change one sibling hash in the path.
    rejected_path = 0
    for proof in proofs[:tamper_samples]:
        if not proof["path"]:
            continue
        forged = json.loads(json.dumps(proof))
        step = forged["path"][0]
        step["hash"] = ("0" if step["hash"][0] != "0" else "1") + step["hash"][1:]
        if not verify_proof(forged):
            rejected_path += 1

    return {
        "leaves": tree["count"],
        "height": tree["height"],
        "root": tree["root"],
        "python_root": python_root,
        "root_matches": root_matches,
        "levels_match": levels_match,
        "proofs": len(proofs),
        "proofs_verified": verified,
        "path_length": len(proofs[0]["path"]) if proofs else 0,
        "tampered_leaves": min(tamper_samples, len(proofs)),
        "rejected_tampered_leaves": rejected_leaf,
        "tampered_paths": min(tamper_samples, len(proofs)),
        "rejected_tampered_paths": rejected_path,
        "build_stdout": build["stdout"],
    }
