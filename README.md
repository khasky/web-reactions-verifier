# Web Reactions Verifier

A standalone, open-source tool that re-derives the Web Reactions counters from the **public** log and checks them against the signed, externally-anchored checkpoint — so the totals are provable, not just promised. It talks only to the public API and the public log; it has no privileged access.

## Install

```
pnpm install
```

## Run

```
node src/verify.mjs --api https://api.webreactions.app \
  --repo https://raw.githubusercontent.com/khasky/web-reactions-log/main \
  --pubkey <LOG_PUBKEY base64> \
  --target github/1
```

- `--api` (required): the public API base URL — serves `/log/*` and `/reactions/count`.
- `--repo` (optional): GitHub raw base of the public log; cross-checks the signed root against the published anchor.
- `--pubkey` (optional if you paste `PINNED_PUBKEY_B64` into `src/verify.mjs`): the published Ed25519 public key.
- `--target site/id` (optional): also compare the re-derived count to the live `/reactions/count` for one target.
- `--limit N` (optional, default 50): cap on the reactions compared in the `--target` check.
- `--ots` (optional): also run the OpenTimestamps→Bitcoin deep audit (below). Needs `--repo`.
- `--btc-api <url>` (optional, with `--ots`): override the Bitcoin block-header source (default: a public explorer).

## What it checks

1. The checkpoint's Ed25519 signature against the pinned public key.
2. (with `--repo`) the signed root matches the public GitHub anchor — catches a "split view" where the API shows you one history and everyone else another.
3. Every log entry is refetched and the Merkle root is recomputed from scratch; it must equal the checkpoint's `root_hash`.
4. The per-target counters are re-derived from the log (accounting for changes and removals); with `--target`, they must equal what the live API serves.
5. The published revocation list matches the revocations actually present in the log.
6. The log is internally consistent — every entry is well-formed and no count is ever driven impossibly negative.
7. (with `--ots`) the matured OpenTimestamps proof anchors the signed root in a Bitcoin block.

Exit code `0` = PASS, `1` = FAIL. A failure means the published numbers don't match the log, or the log doesn't match its signed, anchored checkpoint — exactly what this is built to catch. It checks the **integrity** of the record; it does not, by itself, prove each reaction comes from a unique person — that is a separate concern.

### `--ots`: OpenTimestamps → Bitcoin deep audit

This walks the matured `.ots` proof to a Bitcoin block and confirms the signed checkpoint root was committed there — proof the history couldn't be backdated. It is **opt-in** because it is network-bound (it queries a Bitcoin block explorer) and a checkpoint's Bitcoin attestation only matures hours after the checkpoint is signed. With `--ots` the verifier reads `ots/latest.json`, `ots/<tree_size>.json`, and `ots/<tree_size>.ots` from `--repo`, re-checks the checkpoint signature, then verifies the proof against Bitcoin using [`opentimestamps`](https://www.npmjs.com/package/opentimestamps) (installed by `pnpm install`, loaded only when `--ots` is used). The same `.ots` also verifies with the official `ots verify` CLI.
