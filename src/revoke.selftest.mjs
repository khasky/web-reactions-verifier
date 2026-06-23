// Self-test for the revoke (op=4) track in the standalone verifier.
//   node src/revoke.selftest.mjs
//
// Asserts the verifier's serializeLeaf / foldCounters / checkStructuralInvariants
// are self-consistent on a known revoke example, and prints the resulting hashes.

import {
  bytesToHex,
  checkStructuralInvariants,
  counterKey,
  foldCounters,
  leafHash,
  serializeLeaf,
} from "./transparency.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

// --- KAT: a fixed revoke leaf -------------------------------------------------
const KAT = {
  seq: 42n,
  ts: 1700000000000,
  op: 4,
  site: "github",
  targetId: "gh:o/r",
  reaction: null,
  prevReaction: null,
  userRef: null,
  revokeSeq: 7n,
  reasonCode: "sybil_cluster",
  evidenceHash: Uint8Array.from({ length: 32 }, (_, i) => i), // 0x00..0x1f
};
const canonicalHex = bytesToHex(serializeLeaf(KAT));
const leafHex = bytesToHex(await leafHash(KAT));
console.log(`KAT canonical = ${canonicalHex}`);
console.log(`KAT leaf_hash = ${leafHex}`);

// --- fold: add -> revoke -> re-revoke (idempotent, clamp) ---------------------
const ck = (r) => counterKey("github", "gh:o/r", r);
const evAdd = { seq: 1n, op: 1, site: "github", target_id: "gh:o/r", reaction: "👍", prev_reaction: null };
const evRevoke = { seq: 2n, op: 4, site: "github", target_id: "gh:o/r", revoke_seq: 1n };
const evRevoke2 = { seq: 3n, op: 4, site: "github", target_id: "gh:o/r", revoke_seq: 1n };

check(foldCounters([evAdd]).get(ck("👍")) === 1, "fold: lone add => 1");
check((foldCounters([evAdd, evRevoke]).get(ck("👍")) ?? 0) === 0, "fold: add+revoke => 0");
check(
  (foldCounters([evAdd, evRevoke, evRevoke2]).get(ck("👍")) ?? 0) === 0,
  "fold: add+revoke+re-revoke => 0 (idempotent)",
);
// revoke of an unseen / forward seq is a no-op
check(foldCounters([evRevoke, evAdd]).get(ck("👍")) === 1, "fold: forward revoke is a no-op");
// switch re-credit: add A, switch A->B, revoke the switch => A back to 1, B to 0
const evAddA = { seq: 1n, op: 1, site: "github", target_id: "gh:o/r", reaction: "A", prev_reaction: null };
const evSwitch = { seq: 2n, op: 2, site: "github", target_id: "gh:o/r", reaction: "B", prev_reaction: "A" };
const evRevSwitch = { seq: 3n, op: 4, site: "github", target_id: "gh:o/r", revoke_seq: 2n };
const sw = foldCounters([evAddA, evSwitch, evRevSwitch]);
check((sw.get(ck("A")) ?? 0) === 1 && (sw.get(ck("B")) ?? 0) === 0, "fold: revoke of switch re-credits prev");

// --- invariants D/E -----------------------------------------------------------
const base = [
  { seq: 1, op: 1, site: "s", target_id: "t", reaction: "x", prev_reaction: null, user_ref: "a".repeat(64) },
];
const ok = checkStructuralInvariants([
  ...base,
  { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 1 },
]);
check(ok.length === 0, `invariants: valid revoke passes (${ok.join("; ")})`);
const dangling = checkStructuralInvariants([
  ...base,
  { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 999 },
]);
check(dangling.length === 1, "invariants D: dangling revoke_seq flagged");
const self = checkStructuralInvariants([...base, { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 2 }]);
check(self.length === 1, "invariants D: self-revoke flagged");
const forward = checkStructuralInvariants([
  { seq: 1, op: 4, site: "s", target_id: "t", revoke_seq: 2 },
  { seq: 2, op: 1, site: "s", target_id: "t", reaction: "x", prev_reaction: null, user_ref: "a".repeat(64) },
]);
check(forward.length === 1, "invariants D: forward revoke flagged");
const dbl = checkStructuralInvariants([
  ...base,
  { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 1 },
  { seq: 3, op: 4, site: "s", target_id: "t", revoke_seq: 1 },
]);
check(dbl.length === 1, "invariants E: double-revoke flagged");

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
