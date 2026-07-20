// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the checkpoint-archive replay primitive.
//   node src/archive.selftest.mjs

import { bytesToHex, merkleRootFromLeaves, merkleRootsAtSizes, sha256, utf8 } from "./transparency.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

// merkleRootsAtSizes: prefix roots from one pass must match independent
// per-prefix recomputation — the property the archive replay stands on.
const leaves = [];
for (let i = 0; i < 9; i++) leaves.push(await sha256(utf8(`leaf${i}`)));
const sizes = [1, 2, 3, 5, 8, 9];
const roots = await merkleRootsAtSizes(leaves, sizes);
let prefixOk = true;
for (const s of sizes) {
  const direct = await merkleRootFromLeaves(leaves.slice(0, s));
  if (bytesToHex(roots.get(s)) !== bytesToHex(direct)) prefixOk = false;
}
check(prefixOk, "merkleRootsAtSizes: every prefix root equals a direct recomputation");
check(!roots.has(10), "merkleRootsAtSizes: sizes beyond the leaf count are absent");
check((await merkleRootsAtSizes(leaves, [])).size === 0, "merkleRootsAtSizes: empty size set yields no roots");

// A tampered prefix must change its root (replay would flag the archive).
const tampered = leaves.slice();
tampered[2] = await sha256(utf8("evil"));
const tamperedRoots = await merkleRootsAtSizes(tampered, [5]);
check(bytesToHex(tamperedRoots.get(5)) !== bytesToHex(roots.get(5)), "a tampered leaf changes the prefix root");

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
