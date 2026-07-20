// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the checkpoint-archive replay primitive and the signed daily
// stats file contract.
//   node src/archive.selftest.mjs

import * as ed from "@noble/ed25519";
import { bytesToHex, dailyAggregates, merkleRootFromLeaves, merkleRootsAtSizes, sha256, statsCanonicalBytes, utf8, verifySignature } from "./transparency.mjs";

let failed = false;
const DAY = 86_400_000;
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

// --- signed daily stats contract ---------------------------------------------
// Canonical bytes are the cross-impl contract (workers lib/log-stats.ts) — pin
// them literally.
const stats = { day: "2026-07-18", new_accounts: 5, votes: 42, unique_user_refs: 17, revokes: 3 };
check(
  new TextDecoder().decode(statsCanonicalBytes(stats)) === "web-reactions-stats-v1\nday:2026-07-18\nnew_accounts:5\nvotes:42\nunique_user_refs:17\nrevokes:3\n",
  "stats canonical bytes match the pinned rendering",
);
check(
  new TextDecoder().decode(statsCanonicalBytes({ ...stats, epoch_continuity: { from_epoch: 687, to_epoch: 688, accounts: 12 } })).endsWith("epoch_continuity:687:688:12\n"),
  "epoch continuity appends its canonical line",
);
const priv = ed.utils.randomPrivateKey();
const pubB64 = Buffer.from(await ed.getPublicKeyAsync(priv)).toString("base64");
const sig = await ed.signAsync(statsCanonicalBytes(stats), priv);
check(await verifySignature(pubB64, sig, statsCanonicalBytes(stats)), "stats signature roundtrip verifies");
check(!(await verifySignature(pubB64, sig, statsCanonicalBytes({ ...stats, votes: 43 }))), "a changed aggregate breaks the signature");

// --- dailyAggregates -----------------------------------------------------------
const T = Date.parse("2026-07-18T10:00:00Z");
const agg = dailyAggregates([
  { seq: 1, ts: T, op: 1, user_ref: "a".repeat(64) },
  { seq: 2, ts: T + 1000, op: 2, user_ref: "a".repeat(64) },
  { seq: 3, ts: T + 2000, op: 1, user_ref: "b".repeat(64) },
  { seq: 4, ts: T + 3000, op: 4 },
  { seq: 5, ts: T + DAY, op: 1, user_ref: "c".repeat(64) },
]);
const d1 = agg.get("2026-07-18");
check(d1.votes === 3 && d1.refs.size === 2 && d1.revokes === 1, "dailyAggregates buckets votes/refs/revokes per UTC day");
check(agg.get("2026-07-19").votes === 1, "next-day leaf lands in the next bucket");

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
