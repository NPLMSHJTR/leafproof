# leafproof

**中文简介** — 追加式 Merkle 日志（RFC 6962 风格）：叶子与内部节点用不同前缀哈希，包含证明由 Python 独立重算验证；对伪造叶子和篡改路径两类攻击逐条检查是否被拒绝。

**English** — An append-only Merkle log. Leaves and interior nodes are hashed with different domain prefixes, and every inclusion proof is re-verified by an independent Python implementation. Two tampering attacks are run against every sampled proof.

```console
$ python scripts/demo.py
leafproof 0.1.0  5000 leaves  height 13
root matches Python: True  levels match: True
proofs verified: 626/626
tamper rejected: leaves 200/200, paths 200/200
```

## Why two implementations

A Merkle tree that verifies its own proofs proves nothing. The TypeScript code
builds the tree and emits audit paths; the Python code rebuilds the same tree from
the raw records and checks every level, then verifies each proof by hashing leaf →
root on its own. The two share a specification, not a line of code.

## The specification used

- leaf hash: `SHA-256(0x00 || record)`
- interior hash: `SHA-256(0x01 || left || right)`
- an unpaired node is promoted unchanged, never hashed with itself

The two prefix bytes are the part people skip. Without them, an interior node's
hash could be replayed as a leaf hash, and the proof system would prove the wrong
statement.

## Results

5,000 records, 13 levels, 12 hashes per audit path:

| Check | Result |
| --- | --- |
| Python root equals TypeScript root | yes |
| every level matches | yes |
| inclusion proofs verified | 626/626 |
| forged leaf rejected | 200/200 |
| altered sibling hash rejected | 200/200 |

Both attacks keep the proof structurally valid: the right length, the right
shape, the right root field. They are rejected only by the hash chain, which is
the property worth testing.

## Quick start

```bash
python scripts/demo.py
```

Or by hand:

```bash
node --experimental-strip-types src/tree.ts build --input items.txt --out tree.json
node --experimental-strip-types src/tree.ts prove --tree tree.json --out proofs.json --limit 600
```

`tree.json` contains every level, so a verifier can inspect the shape as well as
the root. For a production log you would publish only the root and the proofs;
the full tree here is a debugging aid.

## Limits

- **Inclusion only.** Consistency proofs between two tree sizes are not
  implemented, so this cannot yet answer "did the log rewrite history".
- **No persistence or gossip.** The log lives in one JSON file; there is no
  append API, no signing, and no witness cosigning.
- **Whole tree in memory.** Fine for thousands of records, not for millions.
- **Not a transparency log.** It is the proof machinery a transparency log would
  use, without the operational parts that make one trustworthy.

## Repository layout

```
src/tree.ts                    hashing, tree construction, proofs, CLI
python/src/leafproof/harness.py independent tree and proof verification
python/src/leafproof/report.py  Markdown report
scripts/demo.py                build, prove, verify, tamper in one command
```

## Development

```bash
PYTHONPATH=python/src python -m unittest discover -s python/tests -t python/tests -v
cd python && pip install -e ".[dev]" && ruff check . && mypy
```

## License

MIT. See [LICENSE](LICENSE).
