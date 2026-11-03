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
 * The scan refuses only what the full decoder refuses too (every failure
 * is INVALID_STRUCTURE, MALFORMED_MESSAGE on the wire, §62 class 1); it
 * accepts nothing the decoder would not check again.
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
    default:
      return fail("a tag or simple value"); // LFCP uses neither inside these structures
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
  p = skip(bytes, p, end); // descriptor, checked by the decoder
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

/** A Device Certificate's COSE_Sign1 in `[start, end)`; returns whether its mask lists 12. */
function scanCertificateAt(bytes: Uint8Array, start: number, end: number): boolean {
  const a = arrayHead(bytes, start, end, "the certificate");
  if (a.value !== 4) fail("the certificate is not a four-element COSE_Sign1");
  let p = bstr(bytes, a.next, end)[1]; // protected header
  p = skip(bytes, p, end); // unprotected header
  const [ps, pe] = bstr(bytes, p, end);
  const managing = scanPayload(bytes, ps, pe);
  p = bstr(bytes, pe, end, 64)[1];
  if (p !== end) fail("bytes follow the certificate");
  return managing;
}

/** Runs `locate`; a shape it does not expect is left to the full decoder (undefined). */
function attempt<T>(locate: () => T): T | undefined {
  try {
    return locate();
  } catch {
    return undefined;
  }
}

/**
 * Checks the bounds of a standalone certificate's exact bytes. A COSE
 * envelope of another shape is left to parseSignedObject; the payload's
 * bounds are refused here.
 */
export function scanDeviceCertificate(bytes: Uint8Array): void {
  const end = bytes.length;
  const payload = attempt(() => {
    const a = head(bytes, 0, end);
    if (a.major !== 4 || a.value !== 4) return undefined;
    const p = skip(bytes, bstr(bytes, a.next, end)[1], end);
    return bstr(bytes, p, end);
  });
  if (payload !== undefined) scanPayload(bytes, payload[0], payload[1]);
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

/** The body key that holds a certificate chain, by Control Record type (§15, §23.3, §17.4). */
const CHAIN_KEY: Readonly<Record<number, number>> = { 0: 5, 6: 2, 9: 1 };

/**
 * Checks the bounds of the certificate chain a Control Record of type 0,
 * 6 or 9 carries, on its exact bytes. Anything that is not the expected
 * shape is left to the full decoder.
 */
export function scanControlRecord(bytes: Uint8Array): void {
  const end = bytes.length;
  const found = attempt(() => {
    const a = head(bytes, 0, end);
    if (a.major !== 4 || a.value !== 4) return undefined;
    const p = skip(bytes, bstr(bytes, a.next, end)[1], end);
    const [ps, pe] = bstr(bytes, p, end);
    const m = head(bytes, ps, pe);
    if (m.major !== 5) return undefined;
    let q = m.next;
    let type: number | undefined;
    let body: number | undefined;
    for (let i = 0; i < m.value; i++) {
      const k = head(bytes, q, pe);
      q = skip(bytes, q, pe);
      if (k.major === 0 && k.value === 3) {
        const t = head(bytes, q, pe);
        if (t.major === 0) type = t.value;
      }
      if (k.major === 0 && k.value === 5) {
        // The body is the last field (keys sort ascending): never walk it here.
        body = q;
        break;
      }
      q = skip(bytes, q, pe);
    }
    const chainKey = type === undefined ? undefined : CHAIN_KEY[type];
    if (chainKey === undefined || body === undefined) return undefined;
    const b = head(bytes, body, pe);
    if (b.major !== 5) return undefined;
    let r = b.next;
    for (let i = 0; i < b.value; i++) {
      const k = head(bytes, r, pe);
      r = skip(bytes, r, pe);
      if (k.major === 0 && k.value === chainKey) return { at: r, end: pe };
      r = skip(bytes, r, pe);
    }
    return undefined;
  });
  if (found !== undefined) scanChainAt(bytes, found.at, found.end);
}
