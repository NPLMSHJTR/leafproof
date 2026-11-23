"""Tests for the independent Merkle implementation."""

from __future__ import annotations

import unittest

from leafproof.harness import build_levels, leaf_hash, node_hash, verify_proof


class HashingTests(unittest.TestCase):
    def test_domain_separation(self) -> None:
        data = b"payload"
        self.assertNotEqual(leaf_hash(data), node_hash(leaf_hash(data), leaf_hash(data)))

    def test_single_leaf_tree(self) -> None:
        levels = build_levels([b"only"])
        self.assertEqual(len(levels), 1)
        self.assertEqual(levels[0][0], leaf_hash(b"only"))

    def test_unpaired_node_is_promoted(self) -> None:
        levels = build_levels([b"a", b"b", b"c"])
        self.assertEqual(levels[1][1], levels[0][2])
        self.assertEqual(len(levels[2]), 1)


class ProofTests(unittest.TestCase):
    def test_every_leaf_verifies(self) -> None:
        items = [f"item-{index}".encode() for index in range(9)]
        levels = build_levels(items)
        for index in range(len(items)):
            proof = {"leaf": levels[0][index], "path": [], "root": levels[-1][0]}
            position = index
            for level in range(len(levels) - 1):
                sibling = position ^ 1
                if sibling < len(levels[level]):
                    proof["path"].append({"hash": levels[level][sibling], "left": sibling < position})
                position //= 2
            self.assertTrue(verify_proof(proof), index)

    def test_forged_leaf_fails(self) -> None:
        levels = build_levels([b"a", b"b"])
        proof = {
            "leaf": leaf_hash(b"forged"),
            "path": [{"hash": levels[0][1], "left": False}],
            "root": levels[-1][0],
        }
        self.assertFalse(verify_proof(proof))


if __name__ == "__main__":
    unittest.main()
