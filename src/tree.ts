#!/usr/bin/env node
/**
 * leafproof: append-only Merkle log with inclusion proofs.
 *
 * Hashing follows RFC 6962: leaves are SHA-256(0x00 || data), interior nodes are
 * SHA-256(0x01 || left || right). The domain-separation bytes are what stop a
 * leaf from being reinterpreted as an interior node.
 *
 * Usage:
 *   node --experimental-strip-types src/tree.ts build --input items.txt --out tree.json
 *   node --experimental-strip-types src/tree.ts prove --tree tree.json --out proofs.json --limit 600
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

type Level = string[];

function leafHash(data: Buffer): string {
  return createHash("sha256").update(Buffer.concat([Buffer.from([0]), data])).digest("hex");
}

function nodeHash(left: string, right: string): string {
  const prefix = Buffer.from([1]);
  return createHash("sha256")
    .update(Buffer.concat([prefix, Buffer.from(left, "hex"), Buffer.from(right, "hex")]))
    .digest("hex");
}

function buildLevels(leaves: Level): Level[] {
  if (leaves.length === 0) throw new Error("tree needs at least one leaf");
  const levels: Level[] = [leaves];
  let current = leaves;
  while (current.length > 1) {
    const next: Level = [];
    for (let index = 0; index < current.length; index += 2) {
      if (index + 1 < current.length) {
        next.push(nodeHash(current[index], current[index + 1]));
      } else {
        // RFC 6962 promotes an unpaired node unchanged; it is not hashed with
        // itself, which would make the tree shape ambiguous.
        next.push(current[index]);
      }
    }
    levels.push(next);
    current = next;
  }
  return levels;
}

type Step = { hash: string; left: boolean };
type Proof = { index: number; leaf: string; path: Step[]; root: string };

function prove(levels: Level[], index: number): Proof {
  let position = index;
  const path: Step[] = [];
  for (let level = 0; level < levels.length - 1; level++) {
    const nodes = levels[level];
    const sibling = position ^ 1;
    if (sibling < nodes.length) {
      path.push({ hash: nodes[sibling], left: sibling < position });
    }
    position = Math.floor(position / 2);
  }
  return { index, leaf: levels[0][index], path, root: levels[levels.length - 1][0] };
}

function verify(proof: Proof): boolean {
  let current = proof.leaf;
  for (const step of proof.path) {
    current = step.left ? nodeHash(step.hash, current) : nodeHash(current, step.hash);
  }
  return current === proof.root;
}

function parseArgs(argv: string[]): Record<string, string> {
  const args: Record<string, string> = {};
  for (let index = 0; index < argv.length; index++) {
    if (!argv[index].startsWith("--")) continue;
    const key = argv[index].slice(2);
    const next = argv[index + 1];
    if (next !== undefined && !next.startsWith("--")) {
      args[key] = next;
      index += 1;
    } else {
      args[key] = "true";
    }
  }
  return args;
}

function main(): number {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);

  if (command === "build") {
    const lines = readFileSync(args.input, "utf8").split("\n").filter((line) => line.length > 0);
    const leaves = lines.map((line) => leafHash(Buffer.from(line, "utf8")));
    const levels = buildLevels(leaves);
    const payload = {
      schema_version: 1,
      count: leaves.length,
      root: levels[levels.length - 1][0],
      height: levels.length - 1,
      levels,
    };
    writeFileSync(args.out, JSON.stringify(payload));
    console.log(`build: ${leaves.length} leaves, height ${levels.length - 1}, root ${payload.root}`);
    return 0;
  }

  if (command === "prove") {
    const tree = JSON.parse(readFileSync(args.tree, "utf8")) as { levels: Level[]; count: number };
    const limit = Number(args.limit ?? 600);
    const step = Math.max(1, Math.floor(tree.count / limit));
    const proofs: Proof[] = [];
    for (let index = 0; index < tree.count; index += step) {
      const proof = prove(tree.levels, index);
      if (!verify(proof)) throw new Error(`internal proof failure at ${index}`);
      proofs.push(proof);
    }
    if (!proofs.some((proof) => proof.index === tree.count - 1)) {
      proofs.push(prove(tree.levels, tree.count - 1));
    }
    writeFileSync(args.out, JSON.stringify({ schema_version: 1, proofs }));
    console.log(`prove: ${proofs.length} proofs, path length ${proofs[0]?.path.length ?? 0}`);
    return 0;
  }

  console.error("usage: tree.ts build|prove ...");
  return 2;
}

process.exit(main());
