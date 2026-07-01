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
npx web-reactions-verify --api https://api.webreactions.app \
  --repo https://raw.githubusercontent.com/khasky/web-reactions-log/main \
  --target github/1
```

…or from a checkout:

```
node src/verify.mjs --api https://api.webreactions.app \
  --repo https://raw.githubusercontent.com/khasky/web-reactions-log/main \
  --target github/1
```

Example result:

```bash
checkpoint: tree_size=12 ts=1782799216388
PASS  checkpoint Ed25519 signature
PASS  GitHub anchor matches signed root (tree_size=12)
PASS  fetched all 12 leaves (got 12)
PASS  every recomputed leaf_hash matches the served leaf (0 mismatch)
PASS  recomputed Merkle root == checkpoint root_hash
folded 11 (site,target,reaction) counters from 12 events
PASS  live /reactions/count matches the fold for github/1
revocations: 0 tombstone(s)
PASS  /log/revocations matches op=4 leaves in the log (0)
PASS  structural invariants hold (0 violation(s))

RESULT: PASS
```

The published signing key is pinned in `src/verify.mjs`, so `--pubkey` is optional
for the main deployment. The current pinned key is:

```text
MZZMvWNdL8MXb0AzSvN3+XYnXeU126NWqfqyoZ1dLkU=
```

Pass `--pubkey` only to verify a different deployment or fork.

- `--api` (required): the public API base URL — serves `/log/*` and `/reactions/count`.
- `--repo` (optional): GitHub raw base of the public log; cross-checks the signed root against the published anchor.
- `--pubkey` (optional): the published Ed25519 public key (base64 raw). Defaults to the key pinned in `src/verify.mjs`.
- `--target site/id` (optional): also compare the re-derived count to the live `/reactions/count` for one target.
- `--limit N` (optional, default 50): cap on the reactions compared in the `--target` check.
- `--ots` (optional): also run the OpenTimestamps→Bitcoin deep audit (below). Needs `--repo`; slower and only passes after an OTS proof has matured.
- `--btc-api <url>` (optional, with `--ots`): override the Bitcoin block-header source (default: a public explorer).
- `--json` (optional): print one machine-readable summary (`{ result, tree_size, ts, checks, duration_sec }`) on stdout instead of the human report — used by the status job below. Human/info lines then go to stderr; the exit code is unchanged.

## What it checks

1. The checkpoint's Ed25519 signature against the pinned public key.
2. (with `--repo`) the signed root matches the public GitHub anchor — catches a "split view" where the API shows you one history and everyone else another.
3. Every log entry is refetched and the Merkle root is recomputed from scratch; it must equal the checkpoint's `root_hash`.
4. The per-target counters are re-derived from the log (accounting for changes and removals); with `--target`, they must equal what the live API serves.
5. The published revocation list matches the revocations actually present in the log.
6. The log is internally consistent — every entry is well-formed and no count is ever driven impossibly negative.
7. (with `--ots`) the matured OpenTimestamps proof anchors the signed root in a Bitcoin block.

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

Exit code `0` = PASS, `1` = FAIL. A failure means the published numbers don't match the log, or the log doesn't match its signed, anchored checkpoint — exactly what this is built to catch. It checks the **integrity** of the record; it does not, by itself, prove each reaction comes from a unique person — that is a separate concern.

### `--ots`: OpenTimestamps → Bitcoin deep audit

This walks the matured `.ots` proof to a Bitcoin block and confirms the signed checkpoint root was committed there — proof the history couldn't be backdated. It is **opt-in** because it is network-bound (it queries a Bitcoin block explorer) and a checkpoint's Bitcoin attestation only matures hours after the checkpoint is signed. With `--ots` the verifier reads `ots/latest.json`, `ots/<tree_size>.json`, and `ots/<tree_size>.ots` from `--repo`, re-checks the checkpoint signature, then verifies the proof against Bitcoin using [`opentimestamps`](https://www.npmjs.com/package/opentimestamps) (installed by `pnpm install`, loaded only when `--ots` is used). The same `.ots` also verifies with the official `ots verify` CLI.

### Status reporting (`--json` + scheduled report)

The verifier doubles as the **independent** check behind the public status page at `webreactions.app/status`. The workflow `.github/workflows/verify-and-report.yml` runs daily (and on demand), executes `node src/verify.mjs --json …` against the public API + log, and POSTs the verdict to the API's `POST /status/ingest` endpoint; the status page renders it as the "Independent verification" component.

To enable it on a fork, set on this repo a **variable** `LOG_PUBKEY` (the published key) and a **secret** `STATUS_INGEST_KEY` (matching the API's secret). The job runs without `--ots` — OpenTimestamps matures over days, and the status page tracks the Bitcoin anchor separately — so a young log isn't reported as failing.

## Self-test

```
pnpm selftest
```

Runs `src/revoke.selftest.mjs`, an offline check of the revocation/`op=4` counter-folding logic
against synthetic fixtures (no network). Exit `0` = PASS.

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

RESULT: PASS
```

## License

[GPL-3.0-or-later](LICENSE).
