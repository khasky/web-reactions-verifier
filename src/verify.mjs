#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone transparency-log verifier.
//
//   node src/verify.mjs --api https://api.webreactions.app \
//     [--repo https://raw.githubusercontent.com/khasky/web-reactions-log/main] \
//     [--pubkey <base64 raw Ed25519>] [--target github/1] [--limit 50] \
//     [--ots] [--btc-api <block explorer base>] [--json]
//
// --json prints a single machine-readable summary on stdout (result + per-check
// pass/fail/skip + tree_size) instead of the human report — used by the status-page
// ingest job. Human/info lines then go to stderr. Exit code is unchanged.
//
// Checks, in order:
//   1. signed checkpoint (STH) Ed25519 signature with the pinned/--pubkey key
//   2. (if --repo) the signed root matches the GitHub anchor  (split-view check)
//   3. every leaf refetched, leaf_hash recomputed, Merkle root == checkpoint root
//   4. counters re-derived; (if --target) compared to live /reactions/count
//   5. structural consistency of the log (well-formed entries, no impossible
//      negative counts) + /log/revocations matches the log
//   6. (if --ots) deep audit: the matured OpenTimestamps proof anchors the signed
//      checkpoint root in a Bitcoin block. Network-bound, so opt-in; needs
//      --repo and the opentimestamps dependency (lazy-loaded).
//
// Exit code 0 = PASS, 1 = FAIL. The core checks (1–5) need only @noble/ed25519;
// --ots additionally lazy-loads opentimestamps.

import {
  bytesToHex,
  checkStructuralInvariants,
  counterKey,
  foldCounters,
  hexToBytes,
  leafHashFromEntry,
  merkleRootFromLeaves,
  verifySth,
} from "./transparency.mjs";

// The published Web Reactions log signing key (base64 raw Ed25519). Pinned so --pubkey is optional.
const PINNED_PUBKEY_B64 = "MZZMvWNdL8MXb0AzSvN3+XYnXeU126NWqfqyoZ1dLkU=";

const ENTRIES_PAGE = 1000;

function arg(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

// --json: emit ONE machine-readable summary on stdout (consumed by the status-page
// ingest job) instead of the human report. The verification LOGIC is unchanged — this
// only adds output formatting + a per-check accumulator. In --json mode the human
// PASS/FAIL + info lines are redirected to stderr so stdout carries only the JSON.
const JSON_MODE = process.argv.includes("--json");
if (JSON_MODE) console.log = (...a) => console.error(...a);

const checks = {};
function record(key, status) {
  if (checks[key] === "fail") return; // sticky: once a key fails it stays failed
  if (status === "fail") {
    checks[key] = "fail";
    return;
  }
  if (checks[key] === undefined || checks[key] === "skip") checks[key] = status;
}

let failed = false;
function check(ok, msg, key) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
  if (key) record(key, ok ? "pass" : "fail");
}

// 6. (optional, --ots) deep audit: the matured OpenTimestamps proof anchors the
//    signed checkpoint root in a Bitcoin block. The .ots is verified with the
//    battle-tested opentimestamps library, imported only on demand.
async function verifyOts(repo, pubkey, btcApi) {
  if (!repo) {
    check(false, "OTS: --ots needs --repo (the .ots proof lives in the log repo)", "ots");
    return;
  }
  let latest;
  try {
    latest = await getJson(`${repo}/ots/latest.json`);
  } catch (e) {
    check(false, `OTS: no matured proof published yet (ots/latest.json: ${e.message})`, "ots");
    return;
  }
  const t = String(latest.tree_size);
  const sidecar = await getJson(`${repo}/ots/${t}.json`);

  // 6a. the sidecar is a real signed checkpoint STH (Ed25519) — no library needed.
  const sigOk = await verifySth(pubkey, hexToBytes(sidecar.signature), {
    treeSize: BigInt(sidecar.tree_size),
    rootHash: hexToBytes(sidecar.root_hash),
    ts: sidecar.ts,
  });
  check(sigOk, `OTS sidecar is a signed checkpoint STH (tree_size=${t})`, "ots");

  // 6b. the .ots proof anchors that exact root in Bitcoin.
  let Ots;
  try {
    const mod = await import("opentimestamps");
    Ots = mod.default ?? mod;
  } catch {
    check(false, "OTS: opentimestamps not installed (run: pnpm install)", "ots");
    return;
  }
  let otsBytes;
  try {
    const res = await fetch(`${repo}/${sidecar.ots_path}`);
    if (!res.ok) throw new Error(`GET ${sidecar.ots_path} -> ${res.status}`);
    otsBytes = Buffer.from(await res.arrayBuffer());
  } catch (e) {
    check(false, `OTS: fetch proof: ${e.message}`, "ots");
    return;
  }
  try {
    const detached = readDetached(Ots, otsBytes);
    const original = Ots.DetachedTimestampFile.fromHash(
      new Ots.Ops.OpSHA256(),
      Buffer.from(sidecar.root_hash, "hex"),
    );
    // --btc-api overrides the block-header source. The exact option key is
    // version-specific (esplora/insight); confirm against the installed README.
    const options = btcApi ? { explorers: [btcApi] } : {};
    const result = await Ots.verify(detached, original, options);
    const att = result?.bitcoin ?? (result && typeof result === "object" ? Object.values(result)[0] : null);
    const height = att?.height ?? sidecar.btc_block_height;
    check(!!att, `OTS: signed root anchored in Bitcoin (block ${height ?? "?"})`, "ots");
  } catch (e) {
    check(false, `OTS Bitcoin verification: ${e.message}`, "ots");
  }
}

// The detached-file deserializer differs across library versions: some take a
// Buffer, some a StreamDeserialization context. Try both.
function readDetached(Ots, bytes) {
  if (Ots.Context?.StreamDeserialization) {
    try {
      return Ots.DetachedTimestampFile.deserialize(new Ots.Context.StreamDeserialization(bytes));
    } catch {
      /* fall through to the buffer form */
    }
  }
  return Ots.DetachedTimestampFile.deserialize(bytes);
}

async function main() {
  const api = arg("--api");
  const repo = arg("--repo");
  const pubkey = arg("--pubkey") || PINNED_PUBKEY_B64;
  const target = arg("--target");
  const limit = arg("--limit") || "50";
  const ots = process.argv.includes("--ots");
  const btcApi = arg("--btc-api");
  if (!api) {
    console.error("usage: node src/verify.mjs --api <url> [--repo <raw base>] [--pubkey <b64>] [--target site/id] [--ots] [--btc-api <url>] [--json]");
    process.exit(2);
  }
  if (!pubkey) {
    console.error("no public key: pass --pubkey <base64> or set PINNED_PUBKEY_B64 in verify.mjs");
    process.exit(2);
  }

  const startedAt = Date.now();
  const cp = await getJson(`${api}/log/checkpoint`);
  const treeSize = Number(cp.tree_size);
  console.log(`checkpoint: tree_size=${cp.tree_size} ts=${cp.ts}`);

  // 1. signature
  const sigOk = await verifySth(pubkey, hexToBytes(cp.signature), {
    treeSize: BigInt(cp.tree_size),
    rootHash: hexToBytes(cp.root_hash),
    ts: cp.ts,
  });
  check(sigOk, "checkpoint Ed25519 signature", "signature");

  // 2. GitHub anchor cross-check
  if (repo) {
    try {
      const latest = await getJson(`${repo}/checkpoints/latest.json`);
      check(
        latest.root_hash === cp.root_hash && String(latest.tree_size) === String(cp.tree_size),
        `GitHub anchor matches signed root (tree_size=${latest.tree_size})`,
        "github_anchor",
      );
    } catch (e) {
      check(false, `GitHub anchor fetch: ${e.message}`, "github_anchor");
    }
  } else {
    console.log("SKIP  GitHub anchor cross-check (no --repo)");
    record("github_anchor", "skip");
  }

  // 3. refetch all leaves, recompute leaf_hash + Merkle root
  const leaves = [];
  const entries = [];
  let leafMismatch = 0;
  for (let from = 1; from <= treeSize; from += ENTRIES_PAGE) {
    const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
    const page = await getJson(`${api}/log/entries?from=${from}&to=${to}`);
    for (const e of page.entries) {
      const leaf = await leafHashFromEntry(e);
      if (bytesToHex(leaf) !== e.leaf_hash) leafMismatch++;
      leaves.push(leaf);
      entries.push(e);
    }
  }
  check(leaves.length === treeSize, `fetched all ${treeSize} leaves (got ${leaves.length})`, "merkle_root");
  check(leafMismatch === 0, `every recomputed leaf_hash matches the served leaf (${leafMismatch} mismatch)`, "merkle_root");
  const root = await merkleRootFromLeaves(leaves);
  check(bytesToHex(root) === cp.root_hash, "recomputed Merkle root == checkpoint root_hash", "merkle_root");

  // 4. fold + optional live counter comparison
  const counts = foldCounters(entries);
  console.log(`folded ${counts.size} (site,target,reaction) counters from ${entries.length} events`);
  if (target) {
    const [site, ...rest] = target.split("/");
    const targetId = rest.join("/");
    const r = await getJson(`${api}/reactions/count?t=${encodeURIComponent(`${site}/${targetId}`)}&limit=${limit}`);
    const live = r.counts ?? {};
    let mismatch = 0;
    const reactions = new Set([
      ...Object.keys(live),
      ...[...counts.keys()]
        .filter((k) => k.startsWith(`${site}\x00${targetId}\x00`))
        .map((k) => k.split("\x00")[2]),
    ]);
    for (const r of reactions) {
      const folded = counts.get(counterKey(site, targetId, r)) ?? 0;
      const served = live[r] ?? 0;
      if (folded !== served) {
        mismatch++;
        console.log(`   mismatch ${r}: folded=${folded} served=${served}`);
      }
    }
    check(mismatch === 0, `live /reactions/count matches the fold for ${target}`, "counters");
  } else {
    record("counters", "skip");
  }

  // 4b. revocation audit surface: the public /log/revocations list must equal the
  //     set of op=4 tombstones we folded from the log.
  try {
    const revList = [];
    for (let from = 1; from <= treeSize; from += ENTRIES_PAGE) {
      const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
      const rev = await getJson(`${api}/log/revocations?from=${from}&to=${to}`);
      revList.push(...(rev.revocations ?? []));
    }
    console.log(`revocations: ${revList.length} tombstone(s)`);
    for (const r of revList.slice(0, 20)) {
      console.log(
        `   revoke seq=${r.seq} -> revoke_seq=${r.revoke_seq} reason=${r.reason_code ?? "-"} target=${r.target?.site}/${r.target?.target_id}`,
      );
    }
    const op4 = entries
      .filter((e) => e.op === 4)
      .map((e) => String(e.seq))
      .sort();
    const listed = revList.map((r) => String(r.seq)).sort();
    check(
      op4.length === listed.length && op4.every((s, i) => s === listed[i]),
      `/log/revocations matches op=4 leaves in the log (${op4.length})`,
      "revocations",
    );
  } catch (e) {
    check(false, `/log/revocations fetch: ${e.message}`, "revocations");
  }

  // 5. structural consistency an honest log always satisfies: entries are
  //    well-formed and no per-(target,reaction) count is ever driven negative.
  const violations = checkStructuralInvariants(entries);
  for (const v of violations.slice(0, 20)) console.log(`   ${v}`);
  if (violations.length > 20) console.log(`   …and ${violations.length - 20} more`);
  check(violations.length === 0, `structural invariants hold (${violations.length} violation(s))`, "invariants");

  // 6. optional OpenTimestamps → Bitcoin deep audit.
  if (ots) await verifyOts(repo, pubkey, btcApi);
  else record("ots", "skip");

  if (JSON_MODE) {
    process.stdout.write(
      JSON.stringify({
        result: failed ? "fail" : "pass",
        tree_size: cp.tree_size,
        ts: Date.now(),
        checks,
        duration_sec: Math.round((Date.now() - startedAt) / 1000),
      }) + "\n",
    );
  } else {
    console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
  }
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error("verifier error:", e);
  process.exit(1);
});
