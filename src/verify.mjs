#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone transparency-log verifier.
//
//   node src/verify.mjs --api https://api.webreactions.app \
//     [--repo https://raw.githubusercontent.com/khasky/web-reactions-log/main] \
//     [--entries api|repo] [--shard-size 10000] \
//     [--pubkey <base64 raw Ed25519>] [--target github/1] [--limit 50] \
//     [--wipe-grace-hours 48] [--ots] [--btc-api <Esplora base>] [--ots-external <bin>] [--json]
//
// --entries repo reads the raw leaves from the log repo's public
// entries/<start>-<end>.ndjson shards instead of the API; combined with --repo
// (and no --api) that is a FULL OFFLINE audit of a clone/mirror — the operator's
// API is not contacted at all (live-counter and /log/revocations endpoint
// comparisons are then skipped; the in-log revoke invariants still run).
//
// --json prints a single machine-readable summary on stdout (result + per-check
// pass/fail/skip + tree_size) instead of the human report — used by the status-page
// ingest job. Human/info lines then go to stderr. Exit code is unchanged.
//
// Checks, in order:
//   1. signed checkpoint (STH) Ed25519 signature with the pinned/--pubkey key
//   1b. checkpoint freshness (--max-checkpoint-age-hours, default 168; 0 disables)
//   2. (if --repo) the signed root matches the GitHub anchor  (split-view check)
//   3. every leaf refetched, leaf_hash recomputed, Merkle root == checkpoint root
//   3b. (if --repo) checkpoint-ARCHIVE replay: every STH ever published to
//       checkpoints/*.ndjson has a valid signature, no two published STHs claim
//       the same tree_size with different roots (equivocation-in-archive), ts is
//       monotone in tree_size, and each archived root equals the root recomputed
//       from today's leaves at that tree_size — i.e. the whole published history
//       lies on ONE append-only line (an internally-consistent rewrite fails here)
//   3c. (if --repo) signed daily stats files (stats/<day>.json): signature over
//       the canonical bytes, gap-free day series, and votes/unique_user_refs/
//       revokes recomputed from the entries (new_accounts / epoch_continuity
//       are operator commitments, shape-checked)
//   3d. (if --rekor, needs --repo) the newest rekor/<tree_size>.json sidecar
//       resolves to a real Sigstore Rekor entry carrying exactly our signed STH
//       bytes, signature, and public key
//   4. counters re-derived; (if --target) compared to live /reactions/count
//   5. structural consistency of the log (well-formed entries, no impossible
//      negative counts) + /log/revocations matches the log + account-wipe
//      completeness (a pseudonym partially revoked is flagged; --wipe-grace-hours)
//   6. (if --ots) deep audit: the matured OpenTimestamps proof anchors the signed
//      checkpoint root in a Bitcoin block. Network-bound, so opt-in; needs
//      --repo and an Esplora-compatible block-header source.
//
// --stats additionally prints a per-day aggregate CSV (votes, unique pseudonyms,
// revocations) derived from the entries alone.
//
// Exit code 0 = PASS, 1 = FAIL. The core checks need only @noble/ed25519;
// --ots is dependency-clean and uses only Node built-ins.

import {
  bytesToHex,
  checkStructuralInvariants,
  checkWipeCompleteness,
  counterKey,
  dailyAggregates,
  foldCounters,
  hexToBytes,
  leafHashFromEntry,
  merkleRootFromLeaves,
  merkleRootsAtSizes,
  sha256,
  statsCanonicalBytes,
  sthBytes,
  verifySignature,
  verifySth,
} from "./transparency.mjs";
import { runExternalOts, verifyDetachedOtsProof } from "./ots-bitcoin.mjs";

// The published Web Reactions log signing key (base64 raw Ed25519). Pinned so --pubkey is optional.
const PINNED_PUBKEY_B64 = "MZZMvWNdL8MXb0AzSvN3+XYnXeU126NWqfqyoZ1dLkU=";

const ENTRIES_PAGE = 1000;
// Fixed shard size of the public entries/ shards (pinned in TRANSPARENCY.md;
// file names are derived from it). Overridable via --shard-size just in case.
const DEFAULT_SHARD_SIZE = 10_000;

function arg(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return undefined;
  const value = process.argv[i + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

async function getText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.text();
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
//    signed checkpoint root in a Bitcoin block. The .ots is verified by the
//    dependency-clean built-in verifier; --ots-external can add an independent
//    official CLI cross-check.
async function verifyOts(repo, pubkey, btcApi, otsExternal) {
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
  let sidecar;
  try {
    sidecar = await getJson(`${repo}/ots/${t}.json`);
  } catch (e) {
    check(false, `OTS sidecar fetch: ${e.message}`, "ots");
    return;
  }

  // 6a. the sidecar is a real signed checkpoint STH (Ed25519) — no library needed.
  const sigOk = await verifySth(pubkey, hexToBytes(sidecar.signature), {
    treeSize: BigInt(sidecar.tree_size),
    rootHash: hexToBytes(sidecar.root_hash),
    ts: sidecar.ts,
  });
  check(sigOk, `OTS sidecar is a signed checkpoint STH (tree_size=${t})`, "ots");

  // 6b. the .ots proof anchors that exact root in Bitcoin.
  let otsBytes;
  try {
    const res = await fetch(`${repo}/${sidecar.ots_path}`);
    if (!res.ok) throw new Error(`GET ${sidecar.ots_path} -> ${res.status}`);
    otsBytes = new Uint8Array(await res.arrayBuffer());
  } catch (e) {
    check(false, `OTS: fetch proof: ${e.message}`, "ots");
    return;
  }

  try {
    const result = await verifyDetachedOtsProof({
      rootHashHex: sidecar.root_hash,
      otsBytes,
      btcApi,
    });
    check(true, `OTS: signed root anchored in Bitcoin (block ${result.height})`, "ots");
    if (sidecar.btc_block_height != null) {
      // A multi-calendar proof anchors in several blocks; the sidecar records one
      // of them (the worker writes the earliest), so accept any anchored height.
      check(
        result.heights.includes(Number(sidecar.btc_block_height)),
        `OTS sidecar block height is anchored by the proof (${sidecar.btc_block_height})`,
        "ots",
      );
    }
  } catch (e) {
    check(false, `OTS Bitcoin verification: ${e.message}`, "ots");
  }

  if (!otsExternal) return;
  try {
    await runExternalOts({
      command: otsExternal,
      rootHashHex: sidecar.root_hash,
      otsBytes,
    });
    check(true, `OTS external verifier passed (${otsExternal})`, "ots_external");
  } catch (e) {
    check(false, `OTS external verifier: ${e.message}`, "ots_external");
  }
}

// --- checkpoint-archive replay (check 3b) ---------------------------------

// Collect every STH ever published to checkpoints/*.ndjson (+ latest.json).
// Directory listing needs the GitHub contents API, so the repo slug is derived
// from the raw.githubusercontent.com base; a non-GitHub --repo skips 3b.
function githubSlugFromRawBase(repo) {
  const m = /^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/?$/.exec(repo);
  return m ? { owner: m[1], repo: m[2], ref: m[3] } : null;
}

// List file names in a log-repo directory via the GitHub contents API.
// Returns { names } on success, { rateLimited: true } when throttled,
// { missing: true } for an absent directory, or null for a non-GitHub base.
// GITHUB_TOKEN (optional) lifts the 60/h unauthenticated api.github.com quota —
// shared CI runner IPs hit it routinely. A rate-limited listing is GitHub
// throttling us, not tamper evidence, so callers downgrade to a skip.
async function listRepoDir(repo, dir) {
  const slug = githubSlugFromRawBase(repo);
  if (!slug) return null;
  const listUrl = `https://api.github.com/repos/${slug.owner}/${slug.repo}/contents/${dir}?ref=${slug.ref}`;
  const token = process.env.GITHUB_TOKEN;
  const res = await fetch(listUrl, { headers: { accept: "application/vnd.github+json", ...(token ? { authorization: `Bearer ${token}` } : {}) } });
  if (res.status === 403 || res.status === 429) return { rateLimited: true };
  if (res.status === 404) return { missing: true };
  if (!res.ok) throw new Error(`GET ${listUrl} -> ${res.status}`);
  const listing = await res.json();
  return { names: (Array.isArray(listing) ? listing : []).map((f) => f.name).filter((n) => typeof n === "string") };
}

async function fetchCheckpointArchive(repo) {
  const listed = await listRepoDir(repo, "checkpoints");
  if (listed === null || listed.rateLimited) return listed;
  const shards = (listed.names ?? []).filter((n) => n.endsWith(".ndjson")).sort();
  const sths = [];
  for (const name of shards) {
    const text = await getText(`${repo}/checkpoints/${name}`);
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        sths.push({ shard: name, ...JSON.parse(t) });
      } catch {
        sths.push({ shard: name, parseError: true });
      }
    }
  }
  return { shards, sths };
}

// Verify the published checkpoint history lies on one append-only line:
// signatures, per-tree_size uniqueness, ts monotonicity, and every archived
// root replayed from today's leaves. `leaves` = recomputed leaf hashes.
// Returns the per-tree_size STH map for downstream checks (--rekor), or null
// when the archive could not be read.
async function verifyCheckpointArchive(repo, pubkey, cp, leaves) {
  let archive;
  try {
    archive = await fetchCheckpointArchive(repo);
  } catch (e) {
    check(false, `checkpoint archive fetch: ${e.message}`, "archive");
    return null;
  }
  if (archive === null) {
    console.log("SKIP  checkpoint-archive replay (--repo is not a raw.githubusercontent.com base)");
    record("archive", "skip");
    return null;
  }
  if (archive.rateLimited) {
    console.log("SKIP  checkpoint-archive replay (GitHub API rate-limited; set GITHUB_TOKEN to lift the quota)");
    record("archive", "skip");
    return null;
  }
  const malformed = archive.sths.filter((s) => s.parseError).length;
  check(malformed === 0, `checkpoint archive parses (${archive.sths.length} STH line(s) in ${archive.shards.length} shard(s))`, "archive");

  // Per-tree_size uniqueness: two published STHs disagreeing on the same
  // tree_size is direct, signed equivocation evidence.
  const bySize = new Map();
  let conflicts = 0;
  for (const s of archive.sths) {
    if (s.parseError) continue;
    const size = String(s.tree_size);
    const prev = bySize.get(size);
    if (prev && (prev.root_hash !== s.root_hash || Number(prev.ts) !== Number(s.ts))) conflicts++;
    if (!prev) bySize.set(size, s);
  }
  check(conflicts === 0, `no two archived STHs disagree on one tree_size (${conflicts} conflict(s))`, "archive");

  let badSig = 0;
  for (const [size, s] of bySize) {
    const ok = await verifySth(pubkey, hexToBytes(s.signature), {
      treeSize: BigInt(size),
      rootHash: hexToBytes(s.root_hash),
      ts: Number(s.ts),
    });
    if (!ok) badSig++;
  }
  check(badSig === 0, `every archived STH signature verifies (${bySize.size} checked, ${badSig} bad)`, "archive");

  const sizes = [...bySize.keys()].map(Number).sort((a, b) => a - b);
  let tsRegressions = 0;
  for (let i = 1; i < sizes.length; i++) {
    if (Number(bySize.get(String(sizes[i])).ts) < Number(bySize.get(String(sizes[i - 1])).ts)) tsRegressions++;
  }
  check(tsRegressions === 0, `archived STH timestamps are monotone in tree_size (${tsRegressions} regression(s))`, "archive");

  const maxSize = sizes.length ? sizes[sizes.length - 1] : 0;
  check(maxSize <= Number(cp.tree_size), `archive never exceeds the live tree (max archived ${maxSize} <= ${cp.tree_size})`, "archive");
  check(bySize.has(String(cp.tree_size)) && bySize.get(String(cp.tree_size)).root_hash === cp.root_hash, "the live checkpoint is present in the archive shards", "archive");

  // The replay: every archived root must be the root of TODAY's first
  // tree_size leaves — all published checkpoints on one append-only history.
  const roots = await merkleRootsAtSizes(leaves, sizes);
  let rootMismatch = 0;
  for (const size of sizes) {
    const got = roots.get(size);
    if (!got || bytesToHex(got) !== bySize.get(String(size)).root_hash) {
      rootMismatch++;
      console.log(`   archive root mismatch at tree_size=${size}`);
    }
  }
  check(rootMismatch === 0, `every archived root replays from today's leaves (${sizes.length} checkpoint(s), ${rootMismatch} mismatch)`, "archive");
  return bySize;
}

// --- signed daily stats files (aggregate transparency) ---------------------

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86_400_000;

// Verify stats/<day>.json commitments: signature over the canonical bytes,
// gap-free day series, and the three log-derivable aggregates recomputed from
// the entries (votes / unique_user_refs / revokes). new_accounts is an
// operator commitment (shape-checked only), as is epoch_continuity (needs the
// secret salt by design).
async function verifyStatsFiles(repo, pubkey, cp, entries) {
  let listed;
  try {
    listed = await listRepoDir(repo, "stats");
  } catch (e) {
    check(false, `stats listing: ${e.message}`, "stats");
    return;
  }
  if (listed === null || listed.rateLimited) {
    console.log(`SKIP  daily stats files (${listed === null ? "--repo is not a raw.githubusercontent.com base" : "GitHub API rate-limited; set GITHUB_TOKEN"})`);
    record("stats", "skip");
    return;
  }
  const days = (listed.names ?? [])
    .filter((n) => n.endsWith(".json") && DAY_RE.test(n.slice(0, -5)))
    .map((n) => n.slice(0, -5))
    .sort();
  if (days.length === 0) {
    console.log("SKIP  daily stats files (none published yet)");
    record("stats", "skip");
    return;
  }

  const perDay = dailyAggregates(entries);
  let bad = 0;
  const flag = (msg) => {
    bad++;
    console.log(`   ${msg}`);
  };
  for (const day of days) {
    let file;
    try {
      file = await getJson(`${repo}/stats/${day}.json`);
    } catch (e) {
      flag(`stats ${day}: fetch failed (${e.message})`);
      continue;
    }
    const { signature, v, ...payload } = file;
    if (v !== 1 || payload.day !== day) {
      flag(`stats ${day}: malformed file (v=${v}, day=${payload.day})`);
      continue;
    }
    for (const k of ["new_accounts", "votes", "unique_user_refs", "revokes"]) {
      if (!Number.isInteger(payload[k]) || payload[k] < 0) flag(`stats ${day}: ${k} missing or negative`);
    }
    const ec = payload.epoch_continuity;
    if (ec !== undefined && !(Number.isInteger(ec?.from_epoch) && Number.isInteger(ec?.to_epoch) && ec.to_epoch === ec.from_epoch + 1 && Number.isInteger(ec?.accounts) && ec.accounts >= 0)) {
      flag(`stats ${day}: malformed epoch_continuity`);
    }
    if (typeof signature !== "string" || !(await verifySignature(pubkey, hexToBytes(signature), statsCanonicalBytes(payload)))) {
      flag(`stats ${day}: signature does not verify`);
      continue;
    }
    // Recompute the derivable aggregates for days the checkpoint fully covers.
    if (Date.parse(`${day}T00:00:00Z`) + DAY_MS <= Number(cp.ts)) {
      const a = perDay.get(day) ?? { votes: 0, refs: new Set(), revokes: 0 };
      if (payload.votes !== a.votes) flag(`stats ${day}: claims votes=${payload.votes}, log has ${a.votes}`);
      if (payload.unique_user_refs !== a.refs.size) flag(`stats ${day}: claims unique_user_refs=${payload.unique_user_refs}, log has ${a.refs.size}`);
      if (payload.revokes !== a.revokes) flag(`stats ${day}: claims revokes=${payload.revokes}, log has ${a.revokes}`);
    }
  }
  // Gap-free series (missed days are backfilled server-side, so an interior
  // hole means a day's commitment was skipped) + the series keeps up with the
  // checkpoint (2-day lag allowance covers the daily publish cadence).
  for (let i = 1; i < days.length; i++) {
    const prev = Date.parse(`${days[i - 1]}T00:00:00Z`);
    const cur = Date.parse(`${days[i]}T00:00:00Z`);
    for (let t = prev + DAY_MS; t < cur; t += DAY_MS) flag(`stats series gap: ${new Date(t).toISOString().slice(0, 10)} missing`);
  }
  const lastDay = Date.parse(`${days[days.length - 1]}T00:00:00Z`);
  if (Number(cp.ts) - (lastDay + DAY_MS) > 2 * DAY_MS) flag(`stats series stale: newest is ${days[days.length - 1]}, checkpoint is ${new Date(Number(cp.ts)).toISOString()}`);
  check(bad === 0, `signed daily stats match the log (${days.length} day(s), ${bad} violation(s))`, "stats");
}

// --- Sigstore Rekor cross-check (--rekor) ----------------------------------

// Confirm the newest rekor/<tree_size>.json sidecar points at a real Rekor
// entry carrying exactly our signed STH bytes — i.e. an independently operated
// public log witnessed this checkpoint. Needs the archive STHs (ts+signature
// live there, not in the sidecar).
async function verifyRekor(repo, pubkey, cp, archiveBySize) {
  if (!archiveBySize) {
    console.log("SKIP  Rekor cross-check (needs the checkpoint archive)");
    record("rekor", "skip");
    return;
  }
  let listed;
  try {
    listed = await listRepoDir(repo, "rekor");
  } catch (e) {
    check(false, `rekor listing: ${e.message}`, "rekor");
    return;
  }
  if (listed === null || listed.rateLimited || listed.missing || (listed.names ?? []).length === 0) {
    console.log("SKIP  Rekor cross-check (no rekor/ sidecars published)");
    record("rekor", "skip");
    return;
  }
  const sizes = listed.names
    .filter((n) => /^\d+\.json$/.test(n))
    .map((n) => Number(n.slice(0, -5)))
    .filter((n) => n <= Number(cp.tree_size))
    .sort((a, b) => a - b);
  const newest = sizes[sizes.length - 1];
  if (!newest) {
    console.log("SKIP  Rekor cross-check (no sidecar at or below the current tree)");
    record("rekor", "skip");
    return;
  }
  try {
    const sidecar = await getJson(`${repo}/rekor/${newest}.json`);
    const sth = archiveBySize.get(String(newest));
    check(!!sth && sidecar.root_hash === sth.root_hash, `rekor sidecar ${newest} matches the archived checkpoint`, "rekor");
    if (!sth) return;
    const rekorUrl = String(sidecar.rekor_url ?? "https://rekor.sigstore.dev").replace(/\/$/, "");
    const entryResp = await getJson(`${rekorUrl}/api/v1/log/entries/${sidecar.rekor_uuid}`);
    const entry = entryResp[sidecar.rekor_uuid] ?? Object.values(entryResp)[0];
    if (!entry?.body) throw new Error("entry has no body");
    const body = JSON.parse(Buffer.from(String(entry.body), "base64").toString("utf8"));
    const spec = body?.spec ?? {};
    const sthB = sthBytes(BigInt(newest), hexToBytes(sth.root_hash), Number(sth.ts));
    let artifactOk = false;
    if (spec.data?.content) {
      artifactOk = Buffer.from(String(spec.data.content), "base64").equals(Buffer.from(sthB));
    } else if (spec.data?.hash?.value) {
      artifactOk = String(spec.data.hash.value).toLowerCase() === bytesToHex(await sha256(sthB));
    }
    check(artifactOk, `Rekor entry ${sidecar.rekor_uuid.slice(0, 12)}… holds the STH bytes of checkpoint ${newest}`, "rekor");
    const sigOk = spec.signature?.content ? Buffer.from(String(spec.signature.content), "base64").equals(Buffer.from(hexToBytes(sth.signature))) : false;
    check(sigOk, "Rekor entry carries our Ed25519 checkpoint signature", "rekor");
    const pem = spec.signature?.publicKey?.content ? Buffer.from(String(spec.signature.publicKey.content), "base64").toString("utf8") : "";
    check(pem.replace(/\s+/g, "").includes(pubkeyDerB64(pubkey).replace(/\s+/g, "")), "Rekor entry public key is the published log key", "rekor");
  } catch (e) {
    check(false, `Rekor cross-check: ${e.message}`, "rekor");
  }
}

// SPKI DER (base64, no PEM armor) of the raw Ed25519 public key — what the PEM
// body inside the Rekor entry must contain.
function pubkeyDerB64(pubRawB64) {
  const prefix = hexToBytes("302a300506032b6570032100");
  const raw = Buffer.from(pubRawB64, "base64");
  return Buffer.concat([Buffer.from(prefix), raw]).toString("base64");
}


// --- raw-leaf sources ------------------------------------------------------

function padSeq(n) {
  return String(n).padStart(12, "0");
}

// Yield /log/entries-shaped rows [1..treeSize] from the API (paged) or from
// the log repo's entries/ shards (offline audit).
async function fetchEntries(api, repo, entriesMode, treeSize, shardSize) {
  const out = [];
  if (entriesMode === "repo") {
    for (let start = 1; start <= treeSize; start += shardSize) {
      const path = `entries/${padSeq(start)}-${padSeq(start + shardSize - 1)}.ndjson`;
      const text = await getText(`${repo}/${path}`);
      for (const line of text.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const e = JSON.parse(t);
        if (Number(e.seq) <= treeSize) out.push(e);
      }
    }
    return out;
  }
  for (let from = 1; from <= treeSize; from += ENTRIES_PAGE) {
    const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
    const page = await getJson(`${api}/log/entries?from=${from}&to=${to}`);
    out.push(...page.entries);
  }
  return out;
}

async function main() {
  const api = arg("--api");
  const repo = arg("--repo");
  const pubkey = arg("--pubkey") || PINNED_PUBKEY_B64;
  const target = arg("--target");
  const limit = arg("--limit") || "50";
  const wipeGraceHours = Number(arg("--wipe-grace-hours") ?? "48");
  const ots = process.argv.includes("--ots");
  const btcApi = arg("--btc-api");
  const otsExternal = arg("--ots-external");
  const entriesMode = arg("--entries") ?? "api";
  const shardSize = Number(arg("--shard-size") ?? DEFAULT_SHARD_SIZE);
  const statsReport = process.argv.includes("--stats");
  const rekor = process.argv.includes("--rekor");
  const maxAgeHours = Number(arg("--max-checkpoint-age-hours") ?? "168");
  if (!Number.isFinite(maxAgeHours) || maxAgeHours < 0) {
    console.error("--max-checkpoint-age-hours needs a non-negative number (0 disables)");
    process.exit(2);
  }
  if (entriesMode !== "api" && entriesMode !== "repo") {
    console.error("--entries must be 'api' or 'repo'");
    process.exit(2);
  }
  if (!Number.isInteger(shardSize) || shardSize < 1) {
    console.error("--shard-size needs a positive integer");
    process.exit(2);
  }
  // --api is optional ONLY for the offline audit (--entries repo + --repo):
  // then the checkpoint comes from the repo's latest.json and every API-only
  // comparison is skipped.
  if (!api && !(entriesMode === "repo" && repo)) {
    console.error("usage: node src/verify.mjs --api <url> [--repo <raw base>] [--entries api|repo] [--shard-size <n>] [--pubkey <b64>] [--target site/id] [--wipe-grace-hours <n>] [--max-checkpoint-age-hours <n>] [--stats] [--rekor] [--ots] [--btc-api <url>] [--ots-external <bin>] [--json]");
    process.exit(2);
  }
  if (entriesMode === "repo" && !repo) {
    console.error("--entries repo needs --repo");
    process.exit(2);
  }
  if (!Number.isFinite(wipeGraceHours) || wipeGraceHours < 0) {
    console.error("--wipe-grace-hours needs a non-negative number");
    process.exit(2);
  }
  if (process.argv.includes("--ots-external") && !otsExternal) {
    console.error("--ots-external needs a command path/name");
    process.exit(2);
  }
  if (otsExternal && !ots) {
    console.error("--ots-external requires --ots");
    process.exit(2);
  }
  if (!pubkey) {
    console.error("no public key: pass --pubkey <base64> or set PINNED_PUBKEY_B64 in verify.mjs");
    process.exit(2);
  }

  const startedAt = Date.now();
  // Offline mode reads the checkpoint under test from the repo anchor itself
  // (same {tree_size, root_hash, ts, signature} shape as /log/checkpoint).
  const cp = api ? await getJson(`${api}/log/checkpoint`) : await getJson(`${repo}/checkpoints/latest.json`);
  const treeSize = Number(cp.tree_size);
  console.log(`checkpoint: tree_size=${cp.tree_size} ts=${cp.ts}${api ? "" : " (from repo latest.json — offline audit)"}`);

  // 1. signature
  const sigOk = await verifySth(pubkey, hexToBytes(cp.signature), {
    treeSize: BigInt(cp.tree_size),
    rootHash: hexToBytes(cp.root_hash),
    ts: cp.ts,
  });
  check(sigOk, "checkpoint Ed25519 signature", "signature");

  // 1b. freshness — a stale checkpoint means the record you are auditing may be
  // a frozen snapshot. A quiet log ages legitimately (checkpoints only advance
  // on new votes), so the threshold is generous and tunable; 0 disables.
  if (maxAgeHours > 0) {
    const ageH = (Date.now() - Number(cp.ts)) / 3_600_000;
    check(ageH <= maxAgeHours, `checkpoint is fresh (${ageH.toFixed(1)}h old, threshold ${maxAgeHours}h — a quiet log ages legitimately; tune --max-checkpoint-age-hours)`, "freshness");
  } else {
    record("freshness", "skip");
  }

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

  // 3. refetch all leaves (API pages or repo shards), recompute leaf_hash +
  //    Merkle root
  const leaves = [];
  const entries = [];
  let leafMismatch = 0;
  for (const e of await fetchEntries(api, repo, entriesMode, treeSize, shardSize)) {
    const leaf = await leafHashFromEntry(e);
    if (bytesToHex(leaf) !== e.leaf_hash) leafMismatch++;
    leaves.push(leaf);
    entries.push(e);
  }
  check(leaves.length === treeSize, `fetched all ${treeSize} leaves (got ${leaves.length}, source: ${entriesMode})`, "merkle_root");
  check(leafMismatch === 0, `every recomputed leaf_hash matches the served leaf (${leafMismatch} mismatch)`, "merkle_root");
  const root = await merkleRootFromLeaves(leaves);
  check(bytesToHex(root) === cp.root_hash, "recomputed Merkle root == checkpoint root_hash", "merkle_root");

  // 3b. checkpoint-archive replay: the whole PUBLISHED history must lie on one
  //     append-only line through today's leaves.
  let archiveBySize = null;
  if (repo) {
    archiveBySize = await verifyCheckpointArchive(repo, pubkey, cp, leaves);
  } else {
    console.log("SKIP  checkpoint-archive replay (no --repo)");
    record("archive", "skip");
  }

  // 3c. signed daily stats files: aggregate commitments vs the log itself.
  if (repo) {
    await verifyStatsFiles(repo, pubkey, cp, entries);
  } else {
    console.log("SKIP  daily stats files (no --repo)");
    record("stats", "skip");
  }

  // 3d. (--rekor) the newest checkpoint anchored to Sigstore Rekor really is
  //     there, carrying exactly our signed STH bytes.
  if (rekor && repo) {
    await verifyRekor(repo, pubkey, cp, archiveBySize);
  } else {
    record("rekor", "skip");
  }

  // --stats: informational per-day aggregate report, derived from the entries
  // alone (the same numbers anyone can recompute without the operator).
  if (statsReport) {
    const perDay = dailyAggregates(entries);
    console.log("day,votes,unique_user_refs,revokes");
    for (const day of [...perDay.keys()].sort()) {
      const a = perDay.get(day);
      console.log(`${day},${a.votes},${a.refs.size},${a.revokes}`);
    }
  }

  // 4. fold + optional live counter comparison
  const counts = foldCounters(entries);
  console.log(`folded ${counts.size} (site,target,reaction) counters from ${entries.length} events`);
  if (target && !api) {
    console.log("SKIP  live counter comparison (offline audit, no --api)");
    record("counters", "skip");
  } else if (target) {
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
  if (!api) {
    console.log("SKIP  /log/revocations comparison (offline audit, no --api)");
    record("revocations", "skip");
  } else {
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
  }

  // 5. structural consistency an honest log always satisfies: entries are
  //    well-formed and no per-(target,reaction) count is ever driven negative.
  const violations = checkStructuralInvariants(entries);
  for (const v of violations.slice(0, 20)) console.log(`   ${v}`);
  if (violations.length > 20) console.log(`   …and ${violations.length - 20} more`);
  check(violations.length === 0, `structural invariants hold (${violations.length} violation(s))`, "invariants");

  // 5b. invariant F — account-wipe completeness. Revocations are whole-account,
  //     so a pseudonym with some but not all of its leaves revoked is flagged
  //     (after the grace window for wipes still in flight at checkpoint time).
  const wipe = checkWipeCompleteness(entries, Number(cp.ts), wipeGraceHours * 3_600_000);
  for (const v of wipe.slice(0, 20)) console.log(`   ${v}`);
  if (wipe.length > 20) console.log(`   …and ${wipe.length - 20} more`);
  check(
    wipe.length === 0,
    `account wipes are complete (${wipe.length} violation(s); grace ${wipeGraceHours}h)`,
    "wipe_completeness",
  );

  // 6. optional OpenTimestamps → Bitcoin deep audit.
  if (ots) await verifyOts(repo, pubkey, btcApi, otsExternal);
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
  process.exitCode = failed ? 1 : 0;
}

main().catch((e) => {
  console.error("verifier error:", e);
  process.exitCode = 1;
});
