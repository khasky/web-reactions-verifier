import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { bytesToHex, hexToBytes } from "./transparency.mjs";
import { BITCOIN_TAG, Reader, applyOp, bytesEq, parseDetached } from "./ots-core.mjs";

const DEFAULT_BTC_API = "https://blockstream.info/api";
const EXTERNAL_TIMEOUT_MS = 120_000;

function cleanBaseUrl(base) {
  return (base || DEFAULT_BTC_API).replace(/\/+$/, "");
}

async function fetchText(url, fetchFn) {
  const res = await fetchFn(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return (await res.text()).trim();
}

async function fetchJson(url, fetchFn) {
  const res = await fetchFn(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

function readBitcoinHeight(payload) {
  const r = new Reader(payload);
  const height = r.varuint();
  if (!r.eof()) throw new Error("ots: trailing bytes in Bitcoin attestation");
  return height;
}

async function collectBitcoinAttestations(msg, stamp, out, errors) {
  for (const a of stamp.attestations) {
    if (!bytesEq(a.tag, BITCOIN_TAG)) continue;
    try {
      out.push({ height: readBitcoinHeight(a.payload), msg });
    } catch (e) {
      errors.push(e.message);
    }
  }
  for (const { op, child } of stamp.ops) {
    try {
      await collectBitcoinAttestations(await applyOp(op, msg), child, out, errors);
    } catch (e) {
      errors.push(e.message);
    }
  }
}

async function blockHeaderByHeight(height, btcApi, fetchFn) {
  const base = cleanBaseUrl(btcApi);
  const hash = await fetchText(`${base}/block-height/${height}`, fetchFn);
  if (!/^[0-9a-f]{64}$/i.test(hash)) throw new Error(`Bitcoin block ${height}: invalid block hash response`);

  const status = await fetchJson(`${base}/block/${hash}/status`, fetchFn);
  if (status?.in_best_chain === false) throw new Error(`Bitcoin block ${height}: not in best chain`);

  const headerHex = await fetchText(`${base}/block/${hash}/header`, fetchFn);
  if (!/^[0-9a-f]{160}$/i.test(headerHex)) throw new Error(`Bitcoin block ${height}: invalid 80-byte header`);
  return { hash, header: hexToBytes(headerHex) };
}

export async function verifyDetachedOtsProof({
  rootHashHex,
  otsBytes,
  btcApi = DEFAULT_BTC_API,
  fetchFn = fetch,
}) {
  const rootHash = hexToBytes(rootHashHex);
  const detached = parseDetached(otsBytes);
  if (!bytesEq(detached.digest, rootHash)) {
    throw new Error(`OTS detached digest ${bytesToHex(detached.digest)} != signed root ${rootHashHex}`);
  }

  const attestations = [];
  const errors = [];
  await collectBitcoinAttestations(detached.digest, detached.stamp, attestations, errors);
  if (attestations.length === 0) {
    const suffix = errors.length ? ` (${errors.slice(0, 3).join("; ")})` : "";
    throw new Error(`OTS: no Bitcoin attestation found${suffix}`);
  }

  const attempts = [];
  for (const att of attestations) {
    try {
      if (att.msg.length !== 32) {
        throw new Error(`attested message is ${att.msg.length} bytes, expected 32-byte merkle root`);
      }
      const { hash, header } = await blockHeaderByHeight(att.height, btcApi, fetchFn);
      const merkleRoot = header.subarray(36, 68);
      if (bytesEq(att.msg, merkleRoot)) {
        return {
          height: att.height,
          blockHash: hash,
          merkleRoot: bytesToHex(merkleRoot),
        };
      }
      attempts.push(`block ${att.height}: merkle_root ${bytesToHex(merkleRoot)} != OTS ${bytesToHex(att.msg)}`);
    } catch (e) {
      attempts.push(`block ${att.height}: ${e.message}`);
    }
  }

  throw new Error(`OTS: no Bitcoin attestation validated (${attempts.join("; ")})`);
}

function spawnCapture(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(reject, new Error(`external OTS verifier timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d) => {
      stdout += d;
      if (stdout.length > 8192) stdout = stdout.slice(-8192);
    });
    child.stderr?.on("data", (d) => {
      stderr += d;
      if (stderr.length > 8192) stderr = stderr.slice(-8192);
    });
    child.on("error", (e) => finish(reject, e));
    child.on("close", (code) => finish(resolve, { code, stdout, stderr }));
  });
}

export async function runExternalOts({
  command,
  commandArgs = [],
  rootHashHex,
  otsBytes,
  timeoutMs = EXTERNAL_TIMEOUT_MS,
}) {
  const dir = await mkdtemp(path.join(tmpdir(), "web-reactions-ots-"));
  const proofPath = path.join(dir, "proof.ots");
  try {
    await writeFile(proofPath, Buffer.from(otsBytes));
    const result = await spawnCapture(command, [...commandArgs, "verify", "-d", rootHashHex, proofPath], timeoutMs);
    if (result.code !== 0) {
      const detail = (result.stderr || result.stdout || "").trim();
      throw new Error(`external OTS verifier exited ${result.code}${detail ? `: ${detail}` : ""}`);
    }
    return result;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export { DEFAULT_BTC_API };
