// Standalone port of the transparency-log byte spec — this file IS the spec for
// the verifier: the canonical, fixed wire formats are defined here, not in a
// separate doc. Any deviation from them would make verification fail.

import * as ed from "@noble/ed25519";

// noble needs a SHA-512; Node's WebCrypto provides it everywhere.
ed.etc.sha512Async = (...m) =>
  crypto.subtle.digest("SHA-512", ed.etc.concatBytes(...m)).then((b) => new Uint8Array(b));

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const LP_NULL = 0xffffffff;
const OP_REVOKE = 4;

const TE = new TextEncoder();

export function utf8(s) {
  return TE.encode(s);
}
export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
export function u8(n) {
  return Uint8Array.of(n & 0xff);
}
export function u32be(n) {
  const o = new Uint8Array(4);
  new DataView(o.buffer).setUint32(0, n >>> 0, false);
  return o;
}
export function u64be(n) {
  const o = new Uint8Array(8);
  new DataView(o.buffer).setBigUint64(0, BigInt(n), false);
  return o;
}
export function lp(s) {
  if (s === null || s === undefined) return u32be(LP_NULL);
  const b = utf8(s);
  return concatBytes(u32be(b.length), b);
}
export function lpb(b) {
  if (b === null || b === undefined) return u32be(LP_NULL);
  return concatBytes(u32be(b.length), b);
}
export function hexToBytes(s) {
  const c = s.startsWith("\\x") ? s.slice(2) : s;
  const out = new Uint8Array(c.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(c.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function bytesToHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
export function base64ToBytes(s) {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export async function sha256(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

export function serializeLeaf(f) {
  const base = concatBytes(
    u64be(f.seq),
    u64be(f.ts),
    u8(f.op),
    lp(f.site),
    lp(f.targetId),
    lp(f.reaction),
    lp(f.prevReaction),
    lp(f.userRef),
  );
  if (f.op !== OP_REVOKE) return base;
  return concatBytes(base, u64be(f.revokeSeq ?? 0), lp(f.reasonCode ?? null), lpb(f.evidenceHash ?? null));
}
export function leafHash(f) {
  return sha256(concatBytes(u8(LEAF_PREFIX), serializeLeaf(f)));
}
export function nodeHash(l, r) {
  return sha256(concatBytes(u8(NODE_PREFIX), l, r));
}

// Incremental (binary-counter) Merkle root over leaf hashes — O(N).
export async function merkleRootFromLeaves(leaves) {
  const fringe = [];
  for (const leaf of leaves) {
    let carry = leaf;
    let level = 0;
    while (fringe[level]) {
      carry = await nodeHash(fringe[level], carry);
      fringe[level] = null;
      level++;
    }
    fringe[level] = carry;
  }
  let root = null;
  for (let l = 0; l < fringe.length; l++) {
    if (!fringe[l]) continue;
    root = root === null ? fringe[l] : await nodeHash(fringe[l], root);
  }
  return root;
}

export function sthBytes(treeSize, rootHash, ts) {
  return concatBytes(u64be(treeSize), rootHash, u64be(ts));
}
export function verifySth(pubRawB64, sigBytes, sth) {
  return ed.verifyAsync(sigBytes, sthBytes(sth.treeSize, sth.rootHash, sth.ts), base64ToBytes(pubRawB64));
}

export function counterKey(site, target, reaction) {
  return `${site}\x00${target}\x00${reaction}`;
}

// log → counters fold (mirrors applyVote math, including op=4 revoke reversal).
export function foldCounters(entries) {
  const counts = new Map();
  const bump = (site, target, reaction, delta) => {
    if (reaction === null || reaction === undefined) return;
    const k = counterKey(site, target, reaction);
    counts.set(k, (counts.get(k) ?? 0) + delta);
  };
  // Index op∈{1,2,3} by seq so a revoke (op=4) can resolve + invert its target.
  const bySeq = new Map();
  const revoked = new Set();
  for (const e of entries) {
    if (e.op === 1) {
      bump(e.site, e.target_id, e.reaction, 1);
      bySeq.set(String(e.seq), e);
    } else if (e.op === 2) {
      bump(e.site, e.target_id, e.reaction, 1);
      bump(e.site, e.target_id, e.prev_reaction, -1);
      bySeq.set(String(e.seq), e);
    } else if (e.op === 3) {
      bump(e.site, e.target_id, e.prev_reaction, -1);
      bySeq.set(String(e.seq), e);
    } else if (e.op === 4) {
      const rk = e.revoke_seq == null ? null : String(e.revoke_seq);
      if (rk === null || revoked.has(rk)) continue; // missing / double-revoke -> no-op
      const t = bySeq.get(rk);
      if (!t) continue; // unseen / not op∈{1,2,3} -> no-op
      revoked.add(rk);
      if (t.op === 1) bump(t.site, t.target_id, t.reaction, -1);
      else if (t.op === 2) {
        bump(t.site, t.target_id, t.reaction, -1);
        bump(t.site, t.target_id, t.prev_reaction, 1);
      } else if (t.op === 3) bump(t.site, t.target_id, t.prev_reaction, 1);
    }
  }
  for (const [k, v] of counts) if (v < 0) counts.set(k, 0);
  return counts;
}

// Structural consistency an honest log always satisfies, replayed from the
// public entries alone. They check that entries follow the log's own rules — i.e.
// integrity of the record, not authenticity of each author.
//
// Returns an array of human-readable violation strings (empty = all hold).
//
// Three independent checks:
//   A. Per-leaf op/field validity.
//   B. A per-author state machine — no double-add, and a stated previous reaction
//      must match the known current one. A switch/remove may legitimately be the
//      first event seen for an author, so that alone is not a violation.
//   C. Global non-negativity of the per-(site, target, reaction) count at every
//      prefix — an honest log never drives a reaction below zero.
export function checkStructuralInvariants(entries) {
  const violations = [];
  const state = new Map(); // `${user_ref}\x00${site}\x00${target}` -> current reaction | null
  const raw = new Map(); // counterKey(site,target,reaction) -> UNCLAMPED running count
  const seen123 = new Set(); // seqs of prior op∈{1,2,3} (invariant D)
  const revokedSeqs = new Set(); // revoke_seqs already cited (invariant E)
  const bump = (site, target, reaction, delta) => {
    const k = counterKey(site, target, reaction);
    const next = (raw.get(k) ?? 0) + delta;
    raw.set(k, next);
    return next;
  };

  for (const e of entries) {
    const op = e.op;

    // A. per-leaf op/field validity
    if (op === 1) {
      if (e.reaction == null || e.prev_reaction != null)
        violations.push(`seq=${e.seq}: malformed add (reaction set, prev_reaction null)`);
    } else if (op === 2) {
      if (e.reaction == null || e.prev_reaction == null || e.reaction === e.prev_reaction)
        violations.push(`seq=${e.seq}: malformed switch (reaction & prev_reaction set and distinct)`);
    } else if (op === 3) {
      if (e.reaction != null || e.prev_reaction == null)
        violations.push(`seq=${e.seq}: malformed remove (reaction null, prev_reaction set)`);
    } else if (op === 4) {
      // D + E (revoke): must cite an existing EARLIER op∈{1,2,3}; no double-revoke.
      const rk = e.revoke_seq == null ? null : String(e.revoke_seq);
      if (rk === null) violations.push(`seq=${e.seq}: revoke missing revoke_seq`);
      else if (!seen123.has(rk))
        violations.push(
          `seq=${e.seq}: revoke_seq=${rk} has no prior add/switch/remove (dangling/forward/self)`,
        );
      else if (revokedSeqs.has(rk)) violations.push(`seq=${e.seq}: double-revoke of seq=${rk}`);
      else revokedSeqs.add(rk);
      continue; // revoke has no B/C state-machine effect
    } else {
      violations.push(`seq=${e.seq}: unexpected op=${op}`);
      continue;
    }

    // B. per-(user_ref, site, target) state machine
    const sk = `${e.user_ref}\x00${e.site}\x00${e.target_id}`;
    const cur = state.get(sk) ?? null;
    if (op === 1) {
      if (cur != null)
        violations.push(`seq=${e.seq}: double-add (user_ref already active=${cur} on this target)`);
      state.set(sk, e.reaction);
    } else if (op === 2) {
      if (cur != null && cur !== e.prev_reaction)
        violations.push(`seq=${e.seq}: switch prev_reaction=${e.prev_reaction} != known current=${cur}`);
      state.set(sk, e.reaction);
    } else if (op === 3) {
      if (cur != null && cur !== e.prev_reaction)
        violations.push(`seq=${e.seq}: remove prev_reaction=${e.prev_reaction} != known current=${cur}`);
      state.set(sk, null);
    }

    // C. global unclamped non-negativity per (site, target, reaction)
    if (op === 1) {
      bump(e.site, e.target_id, e.reaction, 1);
    } else if (op === 2) {
      bump(e.site, e.target_id, e.reaction, 1);
      if (bump(e.site, e.target_id, e.prev_reaction, -1) < 0)
        violations.push(`seq=${e.seq}: count for ${e.prev_reaction} went negative (switch-away exceeds adds)`);
    } else if (op === 3) {
      if (bump(e.site, e.target_id, e.prev_reaction, -1) < 0)
        violations.push(`seq=${e.seq}: count for ${e.prev_reaction} went negative (remove exceeds adds)`);
    }

    seen123.add(String(e.seq)); // op∈{1,2,3} only (op=4 continues earlier)
  }
  return violations;
}

// Recompute a leaf hash from an /log/entries row (does NOT trust row.leaf_hash).
export function leafHashFromEntry(e) {
  if (e.op === OP_REVOKE) {
    // A revoke leaf serializes user_ref as NULL and appends revoke fields; the
    // stored user_ref sentinel in the DB row is NOT part of the canonical bytes.
    return leafHash({
      seq: BigInt(e.seq),
      ts: e.ts,
      op: OP_REVOKE,
      site: e.site,
      targetId: e.target_id,
      reaction: null,
      prevReaction: null,
      userRef: null,
      revokeSeq: e.revoke_seq == null ? 0 : BigInt(e.revoke_seq),
      reasonCode: e.reason_code ?? null,
      evidenceHash: e.evidence_hash ? hexToBytes(e.evidence_hash) : null,
    });
  }
  return leafHash({
    seq: BigInt(e.seq),
    ts: e.ts,
    op: e.op,
    site: e.site,
    targetId: e.target_id,
    reaction: e.reaction,
    prevReaction: e.prev_reaction,
    userRef: e.user_ref,
  });
}
