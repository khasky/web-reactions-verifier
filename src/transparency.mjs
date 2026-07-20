// SPDX-License-Identifier: GPL-3.0-or-later
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

async function appendLeafToFringe(fringe, leaf) {
  let carry = leaf;
  let level = 0;
  while (fringe[level]) {
    carry = await nodeHash(fringe[level], carry);
    fringe[level] = null;
    level++;
  }
  fringe[level] = carry;
}

async function rootOfFringe(fringe) {
  let root = null;
  for (let l = 0; l < fringe.length; l++) {
    if (!fringe[l]) continue;
    root = root === null ? fringe[l] : await nodeHash(fringe[l], root);
  }
  return root;
}

// Incremental (binary-counter) Merkle root over leaf hashes — O(N).
export async function merkleRootFromLeaves(leaves) {
  const fringe = [];
  for (const leaf of leaves) await appendLeafToFringe(fringe, leaf);
  return rootOfFringe(fringe);
}

// Roots of every historical prefix in `sizes`, from ONE pass over the leaves
// (O(N + |sizes|·log N)). Feeds the checkpoint-archive replay: every signed
// tree head ever published must equal the root recomputed at its tree_size
// from today's leaves — i.e. all checkpoints lie on one append-only history.
// Returns Map<size, rootBytes>; sizes beyond leaves.length are absent.
export async function merkleRootsAtSizes(leaves, sizes) {
  const want = new Set(sizes.map(Number));
  const roots = new Map();
  const fringe = [];
  for (let i = 0; i < leaves.length; i++) {
    await appendLeafToFringe(fringe, leaves[i]);
    if (want.has(i + 1)) roots.set(i + 1, await rootOfFringe(fringe));
  }
  return roots;
}

export function sthBytes(treeSize, rootHash, ts) {
  return concatBytes(u64be(treeSize), rootHash, u64be(ts));
}
export function verifySth(pubRawB64, sigBytes, sth) {
  return ed.verifyAsync(sigBytes, sthBytes(sth.treeSize, sth.rootHash, sth.ts), base64ToBytes(pubRawB64));
}
// Generic Ed25519 verification over arbitrary bytes (the daily stats files).
export function verifySignature(pubRawB64, sigBytes, msgBytes) {
  return ed.verifyAsync(sigBytes, msgBytes, base64ToBytes(pubRawB64));
}

// Canonical signed bytes of a daily stats file — the fixed text rendering the
// backend signs (kept in lockstep with workers lib/log-stats.ts). Signing a
// text form, not the JSON bytes, keeps the signature independent of JSON key
// order/whitespace.
export function statsCanonicalBytes(s) {
  let text = `web-reactions-stats-v1\nday:${s.day}\nnew_accounts:${s.new_accounts}\nvotes:${s.votes}\nunique_user_refs:${s.unique_user_refs}\nrevokes:${s.revokes}\n`;
  if (s.epoch_continuity) {
    text += `epoch_continuity:${s.epoch_continuity.from_epoch}:${s.epoch_continuity.to_epoch}:${s.epoch_continuity.accounts}\n`;
  }
  return utf8(text);
}

// Per-UTC-day aggregates derivable from the public entries: reactions (op
// 1/2/3), distinct pseudonyms among them, and revocations (op=4). Used by the
// stats-file cross-check and the --stats report.
export function dailyAggregates(entries) {
  const perDay = new Map(); // YYYY-MM-DD -> { votes, refs:Set, revokes }
  const dayOf = (ts) => new Date(Number(ts)).toISOString().slice(0, 10);
  const bucket = (day) => {
    let b = perDay.get(day);
    if (!b) {
      b = { votes: 0, refs: new Set(), revokes: 0 };
      perDay.set(day, b);
    }
    return b;
  };
  for (const e of entries) {
    if (e.op === 1 || e.op === 2 || e.op === 3) {
      const b = bucket(dayOf(e.ts));
      b.votes++;
      if (e.user_ref != null) b.refs.add(e.user_ref);
    } else if (e.op === 4) {
      bucket(dayOf(e.ts)).revokes++;
    }
  }
  return perDay;
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

// Default grace for an in-progress or crash-resumed account wipe. A wipe is a single
// synchronous request (seconds); a crash is resumed by a later re-POST whose revokes
// carry a fresh ts, restarting the clock. 48h gives two daily verifier runs of slack
// while bounding how long a half-wiped pseudonym can sit unreported. A policy knob,
// not a proof parameter — auditors of a quiescent log may tighten it to 0.
export const WIPE_GRACE_MS = 48 * 3_600_000;

// Invariant F — account-wipe completeness. Revocations are whole-account: the log
// operator has no per-vote reversal, so once ANY op=4 leaf cites a pseudonym's leaf,
// EVERY op∈{1,2,3} leaf carrying that user_ref must be cited by some op=4 leaf. A
// partially revoked pseudonym is the signature of a surgical vote removal dressed up
// as an account operation, so it is flagged. Completeness is per-pseudonym: user_refs
// rotate per epoch and cannot be linked across epochs (a privacy property of the log),
// so each pseudonym of one account is checked independently.
//
// tipTs is the checkpoint ts; a pseudonym whose newest citing revoke is within graceMs
// of it is treated as an in-progress wipe and skipped. A revoke timestamped AFTER the
// checkpoint would keep its pseudonym in grace at every future verification, so it is
// flagged instead of trusted (honest leaves predate the checkpoint that covers them).
//
// Returns an array of human-readable violation strings (empty = all hold).
export function checkWipeCompleteness(entries, tipTs, graceMs = WIPE_GRACE_MS) {
  const violations = [];
  const bySeq = new Map(); // seq -> op∈{1,2,3} entry
  const byRef = new Map(); // user_ref -> op∈{1,2,3} entries
  const cited = new Set(); // seqs cited by any op=4
  const wipedAt = new Map(); // user_ref -> newest citing revoke ts
  for (const e of entries) {
    if (e.op === 1 || e.op === 2 || e.op === 3) {
      bySeq.set(String(e.seq), e);
      if (e.user_ref != null) {
        const list = byRef.get(e.user_ref) ?? [];
        list.push(e);
        byRef.set(e.user_ref, list);
      }
    } else if (e.op === 4) {
      if (Number(e.ts) > tipTs) {
        violations.push(`seq=${e.seq}: revoke ts=${e.ts} is after the checkpoint ts=${tipTs}`);
        continue;
      }
      const t = e.revoke_seq == null ? null : bySeq.get(String(e.revoke_seq));
      if (!t || t.user_ref == null) continue; // dangling/forward -> invariant D reports it
      cited.add(String(t.seq));
      const prev = wipedAt.get(t.user_ref);
      if (prev === undefined || Number(e.ts) > prev) wipedAt.set(t.user_ref, Number(e.ts));
    }
  }
  for (const [ref, newestTs] of wipedAt) {
    if (tipTs - newestTs <= graceMs) continue; // in-progress / recently resumed wipe
    for (const leaf of byRef.get(ref) ?? []) {
      if (!cited.has(String(leaf.seq)))
        violations.push(
          `seq=${leaf.seq}: op=${leaf.op} leaf by wiped user_ref=${String(ref).slice(0, 12)}… not covered by any revoke (account-wipe incomplete)`,
        );
    }
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
