// Minimal, dependency-free OpenTimestamps proof handling mirrored from
// web-reactions-workers/src/lib/ots-core.ts. Keep the wire/codec logic in these
// two files in sync; the public verifier must not import from the private worker
// repository at runtime.
//
// Wire format (matches python-opentimestamps):
//   - varuint: LEB128 unsigned (used for lengths and the block height)
//   - varbytes: varuint(len) || bytes
//   - op:        tag byte; append/prepend additionally carry varbytes(arg)
//   - attestation: 0x00 marker || 8-byte tag || varbytes(payload)
//   - timestamp: items (attestations first, then ops), every item but the last
//                prefixed with 0xff; an attestation item is 0x00||attestation,
//                an op item is op||child-timestamp (recursive)
//   - detached file: HEADER_MAGIC || varuint(1) || 0x08 (sha256) || digest(32) || timestamp

import { bytesToHex as hex, concatBytes, hexToBytes, sha256, utf8 } from "./transparency.mjs";

// Op tags.
const OP_SHA1 = 0x02;
const OP_RIPEMD160 = 0x03;
export const OP_SHA256 = 0x08;
const OP_KECCAK256 = 0x67;
export const OP_APPEND = 0xf0;
export const OP_PREPEND = 0xf1;

const ATTESTATION_MARKER = 0x00;
const FORK = 0xff;

// 8-byte attestation type tags.
export const PENDING_TAG = Uint8Array.of(0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e);
export const BITCOIN_TAG = Uint8Array.of(0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01);

// Detached-timestamp-file header: 0x00 "OpenTimestamps" 0x00 0x00 "Proof" 0x00 <8 magic bytes>.
const HEADER_MAGIC = concatBytes(
  Uint8Array.of(0x00),
  utf8("OpenTimestamps"),
  Uint8Array.of(0x00, 0x00),
  utf8("Proof"),
  Uint8Array.of(0x00),
  Uint8Array.of(0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94),
);

export function bytesEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// --- byte cursor ---------------------------------------------------------

export class Reader {
  pos = 0;
  constructor(buf) {
    this.buf = buf;
  }
  byte() {
    if (this.pos >= this.buf.length) throw new Error("ots: unexpected EOF");
    return this.buf[this.pos++];
  }
  take(n) {
    if (this.pos + n > this.buf.length) throw new Error("ots: unexpected EOF");
    return this.buf.subarray(this.pos, (this.pos += n));
  }
  // LEB128 unsigned. Number math (not <<) so values past 2^31 stay exact.
  varuint() {
    let result = 0;
    let shift = 0;
    let b;
    do {
      b = this.byte();
      result += (b & 0x7f) * 2 ** shift;
      shift += 7;
    } while (b & 0x80);
    return result;
  }
  varbytes() {
    return this.take(this.varuint());
  }
  eof() {
    return this.pos >= this.buf.length;
  }
}

class Writer {
  parts = [];
  byte(n) {
    this.parts.push(n & 0xff);
  }
  bytes(b) {
    for (const x of b) this.parts.push(x);
  }
  varuint(n) {
    let v = n;
    do {
      let b = v & 0x7f;
      v = Math.floor(v / 128);
      if (v) b |= 0x80;
      this.parts.push(b);
    } while (v);
  }
  varbytes(b) {
    this.varuint(b.length);
    this.bytes(b);
  }
  toBytes() {
    return Uint8Array.from(this.parts);
  }
}

// --- parse / serialize ---------------------------------------------------

function parseOp(r, tag) {
  if (tag === OP_APPEND || tag === OP_PREPEND) return { tag, arg: r.varbytes() };
  if (tag === OP_SHA256 || tag === OP_RIPEMD160 || tag === OP_SHA1 || tag === OP_KECCAK256)
    return { tag };
  throw new Error(`ots: unknown op tag 0x${tag.toString(16)}`);
}

function serializeOp(op, w) {
  w.byte(op.tag);
  if (op.tag === OP_APPEND || op.tag === OP_PREPEND) w.varbytes(op.arg ?? new Uint8Array());
}

// Max op-nesting depth for a parsed timestamp tree. Each level of op nesting is
// one recursive parseStamp frame, so an attacker-shaped calendar response with a
// deeply nested op chain could otherwise blow the JS stack.
const MAX_STAMP_DEPTH = 1000;

// Parse a timestamp tree structurally — no hashing, so this stays synchronous.
export function parseStamp(r, depth = 0) {
  if (depth > MAX_STAMP_DEPTH) throw new Error("ots: timestamp nesting too deep");
  const stamp = { attestations: [], ops: [] };
  const item = (tag) => {
    if (tag === ATTESTATION_MARKER) {
      const attTag = r.take(8).slice();
      const payload = r.varbytes().slice();
      stamp.attestations.push({ tag: attTag, payload });
    } else {
      const op = parseOp(r, tag);
      stamp.ops.push({ op, child: parseStamp(r, depth + 1) });
    }
  };
  let tag = r.byte();
  while (tag === FORK) {
    item(r.byte());
    tag = r.byte();
  }
  item(tag);
  return stamp;
}

function cmpBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
function cmpOp(a, b) {
  if (a.tag !== b.tag) return a.tag - b.tag;
  return cmpBytes(a.arg ?? new Uint8Array(), b.arg ?? new Uint8Array());
}
function cmpAtt(a, b) {
  return cmpBytes(a.tag, b.tag) || cmpBytes(a.payload, b.payload);
}

export function serializeStamp(s, w) {
  const emit = [
    ...[...s.attestations].sort(cmpAtt).map((a) => () => {
      w.byte(ATTESTATION_MARKER);
      w.bytes(a.tag);
      w.varbytes(a.payload);
    }),
    ...[...s.ops].sort((x, y) => cmpOp(x.op, y.op)).map(({ op, child }) => () => {
      serializeOp(op, w);
      serializeStamp(child, w);
    }),
  ];
  emit.forEach((write, i) => {
    if (i < emit.length - 1) w.byte(FORK);
    write();
  });
}

// --- detached file -------------------------------------------------------

// Serialize a standard .ots detached timestamp for a sha256 digest.
export function serializeDetached(digest, stamp) {
  const w = new Writer();
  w.bytes(HEADER_MAGIC);
  w.varuint(1); // major version
  w.byte(OP_SHA256); // file-hash op
  w.bytes(digest);
  serializeStamp(stamp, w);
  return w.toBytes();
}

// Parse a .ots detached timestamp; returns the declared digest + the tree.
export function parseDetached(bytes) {
  const r = new Reader(bytes);
  const magic = r.take(HEADER_MAGIC.length);
  if (!bytesEq(magic, HEADER_MAGIC)) throw new Error("ots: bad detached header magic");
  r.varuint(); // major version
  const op = r.byte();
  if (op !== OP_SHA256) throw new Error(`ots: unexpected file-hash op 0x${op.toString(16)}`);
  const digest = r.take(32).slice();
  const stamp = parseStamp(r);
  if (!r.eof()) throw new Error("ots: trailing bytes");
  return { digest, stamp };
}

// --- tree operations -----------------------------------------------------

function attEq(a, b) {
  return bytesEq(a.tag, b.tag) && bytesEq(a.payload, b.payload);
}

// Combine two trees rooted at the same message (used to merge per-calendar
// timestamps and to splice an upgrade response into a pending node).
export function mergeStamp(into, from) {
  for (const a of from.attestations) {
    if (!into.attestations.some((x) => attEq(x, a))) into.attestations.push(a);
  }
  for (const fo of from.ops) {
    const match = into.ops.find((io) => cmpOp(io.op, fo.op) === 0);
    if (match) mergeStamp(match.child, fo.child);
    else into.ops.push(fo);
  }
}

// Apply one op to a message. Only sha256 is needed to reach a calendar/bitcoin
// commitment; ripemd160/sha1/keccak never appear in public-calendar paths, so we
// fail loudly rather than pull a hashing dependency into the verifier.
export async function applyOp(op, msg) {
  switch (op.tag) {
    case OP_APPEND:
      return concatBytes(msg, op.arg ?? new Uint8Array());
    case OP_PREPEND:
      return concatBytes(op.arg ?? new Uint8Array(), msg);
    case OP_SHA256:
      return sha256(msg);
    default:
      throw new Error(`ots: hash op 0x${op.tag.toString(16)} unsupported in commitment path`);
  }
}

// Earliest (minimum) Bitcoin attestation height in the tree, or null if none
// (= still pending). A proof merged from several calendars carries several
// Bitcoin attestations, and serialization reorders the tree — so "first found"
// is nondeterministic. The minimum is stable, and it's the height the sidecar
// records.
export function bitcoinHeight(stamp) {
  let best = null;
  for (const a of stamp.attestations) {
    if (!bytesEq(a.tag, BITCOIN_TAG)) continue;
    const h = new Reader(a.payload).varuint();
    if (best === null || h < best) best = h;
  }
  for (const { child } of stamp.ops) {
    const h = bitcoinHeight(child);
    if (h !== null && (best === null || h < best)) best = h;
  }
  return best;
}

// Reconstruct the pending timestamp from raw calendar /digest responses.
export function reconstructPending(responses) {
  const root = { attestations: [], ops: [] };
  for (const resp of responses) {
    if (resp.length === 0) continue;
    mergeStamp(root, parseStamp(new Reader(resp)));
  }
  return root;
}

// Convenience for callers holding hex.
export function digestFromHex(hexStr) {
  return hexToBytes(hexStr);
}

// Serialize / parse a bare timestamp (calendar-response shape, no file header).
export function encodeStamp(stamp) {
  const w = new Writer();
  serializeStamp(stamp, w);
  return w.toBytes();
}
export function decodeStamp(bytes) {
  return parseStamp(new Reader(bytes));
}

// Attestation constructors (encapsulate the per-type payload framing).
export function pendingAttestation(url) {
  const w = new Writer();
  w.varbytes(utf8(url));
  return { tag: PENDING_TAG.slice(), payload: w.toBytes() };
}
export function bitcoinAttestation(height) {
  const w = new Writer();
  w.varuint(height);
  return { tag: BITCOIN_TAG.slice(), payload: w.toBytes() };
}

export { hex };
