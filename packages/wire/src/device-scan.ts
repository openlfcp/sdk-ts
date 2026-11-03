import { LfcpError } from "@openlfcp/core";
import { MAX_DEPTH } from "./cbor/index.js";

/**
 * Bounds of Device Certificates and certificate chains checked on the raw
 * bytes, before any CBOR value is decoded or any byte string copied
 * (LFCP-WIRE-01 §7.3: chain 1–4, mask 1–32, scope at most 64, fixed field
 * sizes, a managing leaf at most three deep). The full decoders run only
 * after this scan, so a declared count beyond a limit is refused without
 * walking or allocating its elements.
 *
 * The COSE envelope (§10) and the descriptor's fixed fields are checked
 * here too, and a Genesis's null prev is skipped, so no shape reaches the
 * decoder unscanned. The scan refuses only what the full decoder refuses
 * too (COSE_MALFORMED for the envelope, INVALID_STRUCTURE otherwise, both
 * MALFORMED_MESSAGE on the wire, §62 class 1); it accepts nothing the
 * decoder would not check again.
 */

const MAX_CHAIN = 4;
const MAX_MANAGING = 3;
const MAX_MASK = 32;
const MAX_SCOPE = 64;
const LABEL_LENGTH = 19; // "LFCP-DEVICE-CERT-v1"
const DEVICE_MANAGE = 12;

function fail(why: string): never {
  throw new LfcpError("INVALID_STRUCTURE", `invalid device certificate (scan): ${why}`);
}

interface Head {
  readonly major: number;
  /** The argument; a count or length above 2^53 is reported as Infinity. */
  readonly value: number;
  readonly next: number;
}

/** One CBOR head at `pos`, not past `end`. Indefinite and reserved forms are refused. */
function head(bytes: Uint8Array, pos: number, end: number): Head {
  if (pos >= end) fail("truncated");
  const b = bytes[pos] as number;
  const major = b >> 5;
  const ai = b & 31;
  if (ai < 24) return { major, value: ai, next: pos + 1 };
  if (ai > 27) fail("indefinite or reserved length");
  const n = 1 << (ai - 24);
  if (pos + 1 + n > end) fail("truncated");
  let value = 0;
  for (let i = 0; i < n; i++) value = value * 256 + (bytes[pos + 1 + i] as number);
  return {
    major,
    value: Number.isSafeInteger(value) ? value : Number.POSITIVE_INFINITY,
    next: pos + 1 + n,
  };
}

/** The end of the item at `pos`, without decoding it. */
function skip(bytes: Uint8Array, pos: number, end: number, depth = 0): number {
  if (depth > MAX_DEPTH) fail("nested too deeply");
  const h = head(bytes, pos, end);
  switch (h.major) {
    case 0:
    case 1:
      return h.next;
    case 2:
    case 3:
      if (h.value > end - h.next) fail("truncated");
      return h.next + h.value;
    case 4:
    case 5: {
      const items = h.major === 5 ? h.value * 2 : h.value;
      // Every item takes at least one byte: a count beyond the input is refused at once.
      if (items > end - h.next) fail("truncated");
      let p = h.next;
      for (let i = 0; i < items; i++) p = skip(bytes, p, end, depth + 1);
      return p;
    }
    case 7:
      // false, true and null (a Genesis's prev is null, §13.1); the
      // decoder refuses every other simple value and float too (§5.2).
      if (h.value >= 20 && h.value <= 22 && h.next === pos + 1) return h.next;
      return fail("a float or an unused simple value");
    default:
      return fail("a tag"); // LFCP uses none (§5.2 rule 6)
  }
}

/** A byte string head at `pos`: its content range. */
function bstr(bytes: Uint8Array, pos: number, end: number, length?: number): [number, number] {
  const h = head(bytes, pos, end);
  if (h.major !== 2) fail("a byte string was expected");
  if (h.value > end - h.next) fail("truncated");
  if (length !== undefined && h.value !== length) fail(`a ${length}-byte string was expected`);
  return [h.next, h.next + h.value];
}

function arrayHead(bytes: Uint8Array, pos: number, end: number, what: string): Head {
  const h = head(bytes, pos, end);
  if (h.major !== 4) fail(`${what} is not an array`);
  return h;
}

/** The certificate payload array; returns whether its mask lists device/manage. */
function scanPayload(bytes: Uint8Array, start: number, end: number): boolean {
  const a = arrayHead(bytes, start, end, "the payload");
  if (a.value !== 7) fail("the payload has not seven elements");
  let p = a.next;
  const label = head(bytes, p, end);
  if (label.major !== 3 || label.value !== LABEL_LENGTH)
    fail("the label is not LFCP-DEVICE-CERT-v1");
  p = skip(bytes, p, end);
  p = bstr(bytes, p, end, 32)[1]; // root
  p = scanDescriptor(bytes, p, end);
  const kind = head(bytes, p, end);
  if (kind.major !== 0 || kind.value > 2) fail("the kind is not 0, 1 or 2");
  p = kind.next;
  const mask = arrayHead(bytes, p, end, "the mask");
  if (mask.value < 1 || mask.value > MAX_MASK) fail(`the mask holds 1 to ${MAX_MASK} codes`);
  p = mask.next;
  let managing = false;
  for (let i = 0; i < mask.value; i++) {
    const code = head(bytes, p, end);
    if (code.major !== 0) fail("a mask code is not an unsigned integer");
    if (code.value === DEVICE_MANAGE) managing = true;
    p = code.next;
  }
  const scope = arrayHead(bytes, p, end, "the scope");
  if (scope.value > MAX_SCOPE) fail(`the scope holds at most ${MAX_SCOPE} Resources`);
  p = scope.next;
  for (let i = 0; i < scope.value; i++) p = bstr(bytes, p, end, 32)[1];
  p = bstr(bytes, p, end, 16)[1]; // serial
  if (p !== end) fail("bytes follow the payload");
  return managing;
}

/** The device descriptor at `pos`: the closed map {0, 1, 2} of 32-byte strings (§7, §7.3 rule 2). */
function scanDescriptor(bytes: Uint8Array, pos: number, end: number): number {
  const m = head(bytes, pos, end);
  if (m.major !== 5 || m.value !== 3) fail("the descriptor is not a three-field map");
  let p = m.next;
  for (let key = 0; key < 3; key++) {
    const k = head(bytes, p, end);
    if (k.major !== 0 || k.value !== key) fail("the descriptor's keys are not 0, 1 and 2");
    p = bstr(bytes, k.next, end, 32)[1];
  }
  return p;
}

function malformed(why: string): never {
  throw new LfcpError("COSE_MALFORMED", `not a canonical LFCP COSE_Sign1 (scan): ${why}`);
}

/**
 * The payload range of the COSE_Sign1 in `[start, end)`, its envelope
 * checked as parseSignedObject does (§10): a protected header of exactly
 * {1: -8, 4: 32-byte kid}, the empty unprotected map, a present payload
 * and a 64-byte signature. Nothing is decoded or copied.
 */
function envelope(bytes: Uint8Array, start: number, end: number): [number, number] {
  const a = head(bytes, start, end);
  if (a.major !== 4 || a.value !== 4) malformed("not a four-element array");
  const [hs, he] = bstr(bytes, a.next, end);
  const h = head(bytes, hs, he);
  if (h.major !== 5 || h.value !== 2) malformed("protected header must be exactly {1: -8, 4: kid}");
  const alg = head(bytes, h.next, he);
  const algValue = head(bytes, alg.next, he);
  if (alg.major !== 0 || alg.value !== 1 || algValue.major !== 1 || algValue.value !== 7)
    malformed("alg must be -8 (EdDSA)");
  const kid = head(bytes, algValue.next, he);
  if (kid.major !== 0 || kid.value !== 4)
    malformed("protected header must be exactly {1: -8, 4: kid}");
  const k = head(bytes, kid.next, he);
  if (k.major !== 2 || k.value !== 32 || k.next + 32 !== he)
    malformed("kid must be a 32-byte Principal ID");
  const u = head(bytes, he, end);
  if (u.major !== 5 || u.value !== 0) malformed("unprotected header must be the empty map");
  const payload = bstr(bytes, u.next, end);
  const sig = head(bytes, payload[1], end);
  if (sig.major !== 2 || sig.value !== 64) malformed("signature must be 64 bytes");
  if (sig.next + 64 !== end) fail("bytes follow the signature");
  return payload;
}

/** A Device Certificate's COSE_Sign1 in `[start, end)`; returns whether its mask lists 12. */
function scanCertificateAt(bytes: Uint8Array, start: number, end: number): boolean {
  const [ps, pe] = envelope(bytes, start, end);
  return scanPayload(bytes, ps, pe);
}

/**
 * Checks the envelope and the bounds of a standalone certificate on its
 * exact bytes, before parseSignedObject decodes anything.
 */
export function scanDeviceCertificate(bytes: Uint8Array): void {
  scanCertificateAt(bytes, 0, bytes.length);
}

/** A certificate-chain at `pos`: 1–4 certificates, a managing leaf at most three deep. */
function scanChainAt(bytes: Uint8Array, pos: number, end: number): number {
  const a = arrayHead(bytes, pos, end, "the certificate chain");
  if (a.value < 1 || a.value > MAX_CHAIN) fail(`a chain holds 1 to ${MAX_CHAIN} certificates`);
  let p = a.next;
  for (let i = 0; i < a.value; i++) {
    const [cs, ce] = bstr(bytes, p, end);
    const managing = scanCertificateAt(bytes, cs, ce);
    if (i === 0 && managing && a.value > MAX_MANAGING)
      fail(`a managing leaf has at most ${MAX_MANAGING} certificates`);
    p = ce;
  }
  return p;
}

/**
 * The value of unsigned key `key` in the map at `pos`, walking every
 * entry without decoding it (the decoder checks order and duplicates).
 */
function field(bytes: Uint8Array, pos: number, end: number, key: number): number | undefined {
  const m = head(bytes, pos, end);
  if (m.major !== 5) fail("a map was expected");
  if (m.value * 2 > end - m.next) fail("truncated");
  let p = m.next;
  let found: number | undefined;
  for (let i = 0; i < m.value; i++) {
    const k = head(bytes, p, end);
    p = skip(bytes, p, end);
    if (k.major === 0 && k.value === key) found = p;
    p = skip(bytes, p, end);
  }
  return found;
}

/** The body key that holds a certificate chain, by Control Record type (§15, §23.3, §17.4). */
const CHAIN_KEY: Readonly<Record<number, number>> = { 0: 5, 6: 2, 9: 1 };

/**
 * Checks the envelope of a Control Record and the bounds of the
 * certificate chain a record of type 0, 6 or 9 carries, on its exact
 * bytes. Every refusal found is final: nothing is left to the decoder
 * once the scan has seen it.
 */
export function scanControlRecord(bytes: Uint8Array): void {
  const [ps, pe] = envelope(bytes, 0, bytes.length);
  const typeAt = field(bytes, ps, pe, 3);
  if (typeAt === undefined) return;
  const t = head(bytes, typeAt, pe);
  const chainKey = t.major === 0 ? CHAIN_KEY[t.value] : undefined;
  if (chainKey === undefined) return;
  const bodyAt = field(bytes, ps, pe, 5);
  if (bodyAt === undefined) return;
  if (head(bytes, bodyAt, pe).major !== 5) return; // the decoder names the wrong body type
  const chainAt = field(bytes, bodyAt, pe, chainKey);
  if (chainAt !== undefined) scanChainAt(bytes, chainAt, pe);
}
