# Web Reactions Verifier

A standalone, open-source tool that re-derives the Web Reactions counters from the **public** log and checks them against the signed, externally-anchored checkpoint — so the totals are provable, not just promised. It talks only to the public API and the public log; it has no privileged access.

This verifier is paired with the public data repository
[`web-reactions-log`](https://github.com/khasky/web-reactions-log). That repository
holds the signed checkpoints and OpenTimestamps proofs; this repository holds the
code that checks them.

## Install

```
pnpm install
```

## Run

Fast check, without cloning:

```
npx github:khasky/web-reactions-verifier --api https://api.webreactions.app \
  --repo https://raw.githubusercontent.com/khasky/web-reactions-log/main \
  --target github/1
```

…or from a checkout:

```
node src/verify.mjs --api https://api.webreactions.app \
  --repo https://raw.githubusercontent.com/khasky/web-reactions-log/main \
  --target github/1
```

Fully offline audit — no request ever reaches the operator's API; the checkpoint comes from the log repo's `checkpoints/latest.json` and the raw leaves from its public `entries/` shards:

```
node src/verify.mjs --entries repo \
  --repo https://raw.githubusercontent.com/khasky/web-reactions-log/main
```

Example result:

```bash
checkpoint: tree_size=206 ts=1783677643656
PASS  checkpoint Ed25519 signature
PASS  GitHub anchor matches signed root (tree_size=206)
PASS  fetched all 206 leaves (got 206)
PASS  every recomputed leaf_hash matches the served leaf (0 mismatch)
PASS  recomputed Merkle root == checkpoint root_hash
folded 165 (site,target,reaction) counters from 206 events
revocations: 28 tombstone(s)
   revoke seq=176 -> revoke_seq=167 reason=vote_manipulation target=facebook/photo:111111
   revoke seq=177 -> revoke_seq=166 reason=vote_manipulation target=facebook/photo:111112
   revoke seq=178 -> revoke_seq=165 reason=vote_manipulation target=facebook/photo:111113
   revoke seq=179 -> revoke_seq=164 reason=vote_manipulation target=facebook/photo:111114
   revoke seq=180 -> revoke_seq=163 reason=vote_manipulation target=facebook/photo:111115
   revoke seq=181 -> revoke_seq=160 reason=vote_manipulation target=instagram/abc111
   revoke seq=182 -> revoke_seq=158 reason=vote_manipulation target=instagram/abc112
   revoke seq=183 -> revoke_seq=162 reason=vote_manipulation target=instagram/abc113
   revoke seq=184 -> revoke_seq=161 reason=vote_manipulation target=instagram/abc114
   revoke seq=185 -> revoke_seq=168 reason=vote_manipulation target=instagram/abc115
   revoke seq=186 -> revoke_seq=169 reason=vote_manipulation target=instagram/abc115
   revoke seq=187 -> revoke_seq=170 reason=vote_manipulation target=instagram/abc115
   revoke seq=188 -> revoke_seq=171 reason=vote_manipulation target=instagram/abc115
   revoke seq=189 -> revoke_seq=172 reason=vote_manipulation target=instagram/abc115
   revoke seq=190 -> revoke_seq=173 reason=vote_manipulation target=instagram/abc115
   revoke seq=191 -> revoke_seq=174 reason=vote_manipulation target=instagram/abc115
   revoke seq=192 -> revoke_seq=156 reason=vote_manipulation target=instagram/abc116
   revoke seq=193 -> revoke_seq=159 reason=vote_manipulation target=instagram/abc117
   revoke seq=194 -> revoke_seq=175 reason=vote_manipulation target=instagram/abc118
   revoke seq=195 -> revoke_seq=157 reason=vote_manipulation target=instagram/abc119
PASS  /log/revocations matches op=4 leaves in the log (28)
PASS  structural invariants hold (0 violation(s))
PASS  account wipes are complete (0 violation(s); grace 48h)
```

The published signing key is pinned in `src/verify.mjs`, so `--pubkey` is optional
for the main deployment. The current pinned key is:

```text
MZZMvWNdL8MXb0AzSvN3+XYnXeU126NWqfqyoZ1dLkU=
```

Pass `--pubkey` only to verify a different deployment or fork.

- `--api` (required unless running the offline audit below): the public API base URL — serves `/log/*` and `/reactions/count`.
- `--repo` (optional): GitHub raw base of the public log; cross-checks the signed root against the published anchor and replays the full checkpoint archive.
- `--entries api|repo` (optional, default `api`): where to read the raw leaves. `repo` reads the public `entries/<start>-<end>.ndjson` shards from `--repo`; combined with omitting `--api` that is a **fully offline audit** of a clone/mirror — the operator's API is never contacted (the live-counter and `/log/revocations` endpoint comparisons are skipped; the in-log revocation invariants still run).
- `--shard-size N` (optional, default 10000): the fixed entries-shard size (matches the published layout; only needed if a deployment ever changes it).
- `--pubkey` (optional): the published Ed25519 public key (base64 raw). Defaults to the key pinned in `src/verify.mjs`.
- `--target site/id` (optional): also compare the re-derived count to the live `/reactions/count` for one target.
- `--limit N` (optional, default 50): cap on the reactions compared in the `--target` check.
- `--wipe-grace-hours N` (optional, default 48): grace window for the account-wipe completeness check — a pseudonym whose newest revocation is younger than this (relative to the checkpoint) counts as a wipe still in flight. A policy knob, not a proof parameter; auditors of a quiescent log may tighten it to `0`.
- `--max-checkpoint-age-hours N` (optional, default 168, `0` disables): flag a checkpoint older than this — a frozen snapshot passing every other check is still a stale view. A quiet log ages legitimately (checkpoints only advance on new votes), hence the generous default.
- `--stats` (optional): print a per-day CSV (reactions, distinct pseudonymous authors, revocations) derived from the entries alone.
- `--rekor` (optional, needs `--repo`): cross-check the newest `rekor/<tree_size>.json` sidecar against the actual Sigstore Rekor entry — an independently operated public log must hold exactly our signed checkpoint bytes.
- `--ots` (optional): also run the OpenTimestamps→Bitcoin deep audit (below). Needs `--repo`; slower and only passes after an OTS proof has matured.
- `--btc-api <url>` (optional, with `--ots`): override the Esplora-compatible Bitcoin block-header source (default: `https://blockstream.info/api`).
- `--ots-external <bin>` (optional, with `--ots`): also cross-check the same proof with an external OpenTimestamps CLI such as `ots`.
- `--json` (optional): print one machine-readable summary (`{ result, tree_size, ts, checks, duration_sec }`) on stdout instead of the human report — used by the status job below. Human/info lines then go to stderr; the exit code is unchanged.

## What it checks

1. The checkpoint's Ed25519 signature against the pinned public key.
2. The checkpoint is fresh (`--max-checkpoint-age-hours`) — a frozen-but-consistent snapshot is flagged, not silently accepted.
3. (with `--repo`) the signed root matches the public GitHub anchor — catches a "split view" where the API shows you one history and everyone else another.
4. Every log entry is refetched and the Merkle root is recomputed from scratch; it must equal the checkpoint's `root_hash`.
5. (with `--repo`) the **checkpoint archive replays**: every checkpoint ever published to `checkpoints/*.ndjson` has a valid signature, no two published checkpoints disagree on one `tree_size`, timestamps are monotone, and every archived root equals the root recomputed from today's leaves at that `tree_size` — so the entire published history lies on ONE append-only line, and even an internally-consistent rewrite of the log fails.
6. (with `--repo`) the **signed daily stats files** (`stats/<day>.json`) hold: the signature covers the canonical bytes, the day series is gap-free and keeps up with the checkpoint, and the log-derivable aggregates (`votes`, `unique_user_refs`, `revokes`) are recomputed from the entries and must match. `new_accounts` is the operator's irreversible public commitment (shape-checked), as is the monthly `epoch_continuity` count.
7. The per-target counters are re-derived from the log (accounting for changes and removals); with `--target`, they must equal what the live API serves.
8. The published revocation list matches the revocations actually present in the log.
9. The log is internally consistent — every entry is well-formed and no count is ever driven impossibly negative.
10. Account wipes are complete — revocations are whole-account, so once any entry of a pseudonym is revoked, every entry of that pseudonym must be revoked. A partially revoked pseudonym is flagged, after a 48-hour grace window for wipes still in flight (`--wipe-grace-hours`).
11. (with `--rekor`) the newest Rekor sidecar resolves to a real Sigstore Rekor entry carrying exactly our signed checkpoint bytes, signature, and public key.
12. (with `--ots`) the matured OpenTimestamps proof anchors the signed root in a Bitcoin block.

### Revocations and account deletion

The log records counter-changing events, not just final state:

- `op=1` — a reaction was added.
- `op=2` — a reaction was changed; the leaf records both the new reaction and
  the previous one.
- `op=3` — a reaction was removed by the user.
- `op=4` — a revocation tombstone: a later public leaf that reverses an earlier
  `op=1`, `op=2`, or `op=3` leaf.

So a normal user "unreact" is `op=3`, not a tombstone. Tombstones are for
append-only corrections. If an account is erased, or if a counted reaction has
to be reversed, Web Reactions does not edit or delete the original log leaf. It
appends an `op=4` revocation leaf instead:

- `revoke_seq` points at the original `op=1/2/3` leaf being reversed.
- `reason_code` is a public machine-readable reason, such as `erasure_self`,
  `erasure_admin`, or an abuse-correction label.
- `evidence_hash` may pin a published evidence report; it is `null` for routine
  account erasure.

The verifier resolves each `revoke_seq` to the original leaf, applies the
inverse effect while folding counters, checks that revokes are not dangling,
forward, self-referential, or duplicated, and confirms that
`GET /log/revocations` matches the `op=4` leaves actually present in the
anchored log.

Revocations are whole-account. There is no per-vote reversal: erasing or
deactivating an account revokes every entry that account wrote. The verifier
enforces this as its account-wipe completeness check — if any entry of a
pseudonym is cited by a revocation, all of that pseudonym's entries must be,
so a single inconvenient vote cannot be quietly reversed under an
account-operation label. Pseudonyms rotate per epoch, so completeness is
checked per pseudonym; linking pseudonyms across epochs is impossible by
design, as a privacy property of the log.

Exit code `0` = PASS, `1` = FAIL. A failure means the published numbers don't match the log, or the log doesn't match its signed, anchored checkpoint — exactly what this is built to catch. It checks the **integrity** of the record; it does not, by itself, prove each reaction comes from a unique person — that is a separate concern.

### `--ots`: OpenTimestamps → Bitcoin deep audit

This walks the matured `.ots` proof to a Bitcoin block and confirms the signed checkpoint root was committed there — proof the history couldn't be backdated. It is **opt-in** because it is network-bound (it queries a Bitcoin block explorer) and a checkpoint's Bitcoin attestation only matures hours after the checkpoint is signed.

With `--ots` the verifier reads `ots/latest.json`, `ots/<tree_size>.json`, and `ots/<tree_size>.ots` from `--repo`, re-checks the checkpoint signature, parses the OpenTimestamps proof locally, and checks that the proof's Bitcoin commitment equals the merkle root in the attested block header. The built-in path has no `opentimestamps` npm dependency.

By default `--btc-api` is `https://blockstream.info/api`; any Esplora-compatible API can be used instead. For an independent cross-check, install the official Python OpenTimestamps client and pass `--ots-external ots`; the verifier will also run `ots verify -d <root_hash> <proof.ots>` against the same proof.

### Status reporting (`--json` + scheduled report)

The verifier doubles as the **independent** check behind the public status page at `webreactions.app/status`. The workflow `.github/workflows/verify-and-report.yml` runs daily (and on demand), executes `node src/verify.mjs --json …` against the public API + log, and POSTs the verdict to the API's `POST /status/ingest` endpoint; the status page renders it as the "Independent verification" component.

To enable it on a fork, set on this repo a **variable** `LOG_PUBKEY` (the published key) and a **secret** `STATUS_INGEST_KEY` (matching the API's secret). The job runs without `--ots` — OpenTimestamps matures over days, and the status page tracks the Bitcoin anchor separately — so a young log isn't reported as failing.

### Fork and audit

You don't need the ingest secret to become an independent watcher: **fork this repository, enable Actions on the fork, and set the `LOG_PUBKEY` variable** — your fork then runs the full verification daily on infrastructure the operator doesn't control, and the run history on your fork is your own public audit trail (the report step simply skips without `STATUS_INGEST_KEY`). The more independent forks watching, the less anyone has to take the operator's word for anything.

## Self-test

```
pnpm selftest
```

Runs `src/revoke.selftest.mjs`, `src/ots.selftest.mjs`, and `src/archive.selftest.mjs` — offline checks of the revocation/`op=4` counter-folding logic, the dependency-clean OTS verifier, the checkpoint-archive replay primitive, and the signed daily-stats contract (canonical bytes + signature) against synthetic fixtures (no network). Exit `0` = PASS.

Example result:

```bash
KAT canonical = 000000000000002a0000018bcfe5680004000000066769746875620000000667683a6f2f72ffffffffffffffffffffffff00000000000000070000000d737962696c5f636c757374657200000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
KAT leaf_hash = c14251e5131e9899fc7dda73a952a79c8ced0fce1f925811e271e482243b7da9
PASS  fold: lone add => 1
PASS  fold: add+revoke => 0
PASS  fold: add+revoke+re-revoke => 0 (idempotent)
PASS  fold: forward revoke is a no-op
PASS  fold: revoke of switch re-credits prev
PASS  invariants: valid revoke passes ()
PASS  invariants D: dangling revoke_seq flagged
PASS  invariants D: self-revoke flagged
PASS  invariants D: forward revoke flagged
PASS  invariants E: double-revoke flagged
PASS  invariant F: complete wipe passes
PASS  invariant F: partial wipe flagged after grace
PASS  invariant F: partial wipe within grace passes
PASS  invariant F: un-wiped pseudonyms are not checked
PASS  invariant F: a resumed wipe's newest revoke restarts the grace clock
PASS  invariant F: revoke timestamped after the checkpoint is flagged
PASS  invariant F: dangling revoke left to invariant D (no double-report)

RESULT: PASS
```

## License

[GPL-3.0-or-later](LICENSE).
