#!/usr/bin/env node
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  OP_APPEND,
  OP_SHA256,
  bitcoinAttestation,
  parseDetached,
  serializeDetached,
} from "./ots-core.mjs";
import { runExternalOts, verifyDetachedOtsProof } from "./ots-bitcoin.mjs";
import { bytesToHex, concatBytes, sha256, utf8 } from "./transparency.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

async function expectReject(promise, pattern, msg) {
  try {
    await promise;
    check(false, msg);
  } catch (e) {
    check(pattern.test(e.message), `${msg} (${e.message})`);
  }
}

function response(body, status = 200) {
  return new Response(body, { status });
}

function headerHexForMerkleRoot(merkleRoot) {
  const header = new Uint8Array(80);
  header.set(merkleRoot, 36);
  return bytesToHex(header);
}

function fetchFor({ headerHex, inBestChain = true, blockHash = "11".repeat(32) }) {
  return async (url) => {
    if (url.endsWith("/block-height/800002")) return response(blockHash);
    if (url.endsWith(`/block/${blockHash}/status`)) return response(JSON.stringify({ in_best_chain: inBestChain }));
    if (url.endsWith(`/block/${blockHash}/header`)) return response(headerHex);
    return response("not found", 404);
  };
}

// Serve several blocks at once: { [height]: { hash, headerHex } }.
function fetchForBlocks(blocks) {
  return async (url) => {
    for (const [height, b] of Object.entries(blocks)) {
      if (url.endsWith(`/block-height/${height}`)) return response(b.hash);
      if (url.endsWith(`/block/${b.hash}/status`)) return response(JSON.stringify({ in_best_chain: true }));
      if (url.endsWith(`/block/${b.hash}/header`)) return response(b.headerHex);
    }
    return response("not found", 404);
  };
}

async function proofFixture({ multiBranch = false, unsupportedOnly = false } = {}) {
  const root = await sha256(utf8("checkpoint-root"));
  const salt = utf8("calendar-salt");
  const attested = await sha256(concatBytes(root, salt));
  const validBranch = {
    op: { tag: OP_APPEND, arg: salt },
    child: {
      attestations: [],
      ops: [{ op: { tag: OP_SHA256 }, child: { attestations: [bitcoinAttestation(800002)], ops: [] } }],
    },
  };
  const unsupportedBranch = {
    op: { tag: 0x02 },
    child: { attestations: [bitcoinAttestation(800002)], ops: [] },
  };
  const ops = unsupportedOnly ? [unsupportedBranch] : multiBranch ? [unsupportedBranch, validBranch] : [validBranch];
  const stamp = { attestations: [], ops };
  return {
    root,
    rootHex: bytesToHex(root),
    attested,
    otsBytes: serializeDetached(root, stamp),
  };
}

async function main() {
  const fixture = await proofFixture();
  const parsed = parseDetached(fixture.otsBytes);
  check(bytesToHex(parsed.digest) === fixture.rootHex, "OTS detached parse returns the signed root digest");

  const ok = await verifyDetachedOtsProof({
    rootHashHex: fixture.rootHex,
    otsBytes: fixture.otsBytes,
    fetchFn: fetchFor({ headerHex: headerHexForMerkleRoot(fixture.attested) }),
  });
  check(ok.height === 800002, "built-in OTS verifier accepts a valid Bitcoin attestation");

  await expectReject(
    verifyDetachedOtsProof({
      rootHashHex: "00".repeat(32),
      otsBytes: fixture.otsBytes,
      fetchFn: fetchFor({ headerHex: headerHexForMerkleRoot(fixture.attested) }),
    }),
    /detached digest/,
    "built-in OTS verifier rejects a digest mismatch",
  );

  await expectReject(
    verifyDetachedOtsProof({
      rootHashHex: fixture.rootHex,
      otsBytes: fixture.otsBytes,
      fetchFn: fetchFor({ headerHex: headerHexForMerkleRoot(new Uint8Array(32)) }),
    }),
    /merkle_root/,
    "built-in OTS verifier rejects a wrong Bitcoin merkle root",
  );

  await expectReject(
    verifyDetachedOtsProof({
      rootHashHex: fixture.rootHex,
      otsBytes: fixture.otsBytes,
      fetchFn: fetchFor({ headerHex: "00", inBestChain: true }),
    }),
    /invalid 80-byte header/,
    "built-in OTS verifier rejects a malformed block header",
  );

  await expectReject(
    verifyDetachedOtsProof({
      rootHashHex: fixture.rootHex,
      otsBytes: fixture.otsBytes,
      fetchFn: fetchFor({ headerHex: headerHexForMerkleRoot(fixture.attested), inBestChain: false }),
    }),
    /not in best chain/,
    "built-in OTS verifier rejects a non-best-chain block",
  );

  const unsupported = await proofFixture({ unsupportedOnly: true });
  await expectReject(
    verifyDetachedOtsProof({
      rootHashHex: unsupported.rootHex,
      otsBytes: unsupported.otsBytes,
      fetchFn: fetchFor({ headerHex: headerHexForMerkleRoot(unsupported.attested) }),
    }),
    /no Bitcoin attestation found|unsupported/,
    "built-in OTS verifier fails closed on unsupported-only paths",
  );

  const multi = await proofFixture({ multiBranch: true });
  const multiOk = await verifyDetachedOtsProof({
    rootHashHex: multi.rootHex,
    otsBytes: multi.otsBytes,
    fetchFn: fetchFor({ headerHex: headerHexForMerkleRoot(multi.attested) }),
  });
  check(multiOk.height === 800002, "built-in OTS verifier accepts one valid branch among invalid branches");

  // Two calendars → two valid attestations in different blocks, the LATER one
  // first in tree order. The verifier must report the earliest anchored height
  // and list every anchored height, so the sidecar's recorded height can be
  // checked against the full set (verify.mjs step 6b).
  const rootTwo = await sha256(utf8("checkpoint-root-two"));
  const saltTwo = utf8("cal-two");
  const attestedA = await sha256(rootTwo);
  const attestedB = await sha256(concatBytes(rootTwo, saltTwo));
  const stampTwo = {
    attestations: [],
    ops: [
      { op: { tag: OP_SHA256 }, child: { attestations: [bitcoinAttestation(800007)], ops: [] } },
      {
        op: { tag: OP_APPEND, arg: saltTwo },
        child: {
          attestations: [],
          ops: [{ op: { tag: OP_SHA256 }, child: { attestations: [bitcoinAttestation(800003)], ops: [] } }],
        },
      },
    ],
  };
  const twoOk = await verifyDetachedOtsProof({
    rootHashHex: bytesToHex(rootTwo),
    otsBytes: serializeDetached(rootTwo, stampTwo),
    fetchFn: fetchForBlocks({
      800003: { hash: "22".repeat(32), headerHex: headerHexForMerkleRoot(attestedB) },
      800007: { hash: "33".repeat(32), headerHex: headerHexForMerkleRoot(attestedA) },
    }),
  });
  check(twoOk.height === 800003, "built-in OTS verifier reports the earliest of several anchored blocks");
  check(twoOk.heights.join(",") === "800003,800007", "built-in OTS verifier lists every anchored height ascending");

  const dir = await mkdtemp(path.join(tmpdir(), "web-reactions-ots-selftest-"));
  try {
    const okHelper = path.join(dir, "ots-ok.mjs");
    const failHelper = path.join(dir, "ots-fail.mjs");
    await writeFile(
      okHelper,
      "import { readFileSync } from 'node:fs';\nconst args = process.argv.slice(2);\nif (args[0] !== 'verify' || args[1] !== '-d' || !/^[0-9a-f]{64}$/i.test(args[2] || '') || readFileSync(args[3]).length === 0) process.exit(2);\n",
    );
    await writeFile(failHelper, "console.error('forced external verifier failure');\nprocess.exit(7);\n");

    await runExternalOts({
      command: process.execPath,
      commandArgs: [okHelper],
      rootHashHex: fixture.rootHex,
      otsBytes: fixture.otsBytes,
      timeoutMs: 5_000,
    });
    check(true, "external OTS runner accepts a successful helper");

    await expectReject(
      runExternalOts({
        command: process.execPath,
        commandArgs: [failHelper],
        rootHashHex: fixture.rootHex,
        otsBytes: fixture.otsBytes,
        timeoutMs: 5_000,
      }),
      /exited 7/,
      "external OTS runner reports helper failure",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }

  console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error("OTS selftest error:", e);
  process.exit(1);
});
