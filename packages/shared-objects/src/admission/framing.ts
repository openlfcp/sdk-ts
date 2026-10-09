import * as A from "@automerge/automerge";
import { LfcpError, toHex } from "@openlfcp/core";
import { ProfileInvalidError } from "../profile-invalid.js";
import { checkCanonicalChange, type ParsedChange } from "./canonical.js";
import { checkChangeExpansion } from "./limits.js";

/**
 * Automerge byte checks of the SHARED-OBJECTS-PROFILE-01 payloads (LFCP-031):
 * a Data Unit plaintext carries exactly one Automerge change (§11, §12), a
 * Snapshot plaintext one Automerge full save (§13). The framing itself is
 * frameProfilePayload / unframeProfilePayload (LFCP-030); this adds the
 * check that the framed bytes are what they claim to be.
 *
 * Automerge storage chunks start with the magic bytes 85 6f 4a 83, a 4-byte
 * checksum (the first 4 bytes of the chunk hash) and a chunk type: 0 for a
 * document (a full save), 1 for a change, 2 for a compressed change.
 */

const MAGIC = [0x85, 0x6f, 0x4a, 0x83];
const CHUNK_DOCUMENT = 0;
const CHUNK_CHANGE = 1;
const CHUNK_COMPRESSED_CHANGE = 2;
const HEADER = 9; // magic, checksum, chunk type

/** §11, §13, §74.1: PROFILE_INVALID / INVALID_AUTOMERGE_BYTES. */
const reject = (why: string): never => {
  throw new ProfileInvalidError("INVALID_AUTOMERGE_BYTES", why);
};

function chunkType(bytes: Uint8Array, what: string): number {
  if (bytes.length < HEADER || MAGIC.some((b, i) => bytes[i] !== b))
    return reject(`${what} is not an Automerge chunk`);
  return bytes[8] as number;
}

/** A checked Automerge change: its bytes and decoded header. */
export interface CheckedChange {
  readonly bytes: Uint8Array;
  /** Hex SHA-256 change hash (the Automerge change identity). */
  readonly hash: string;
  /** Hex actor ID. */
  readonly actor: string;
  readonly seq: number;
  /** Hex hashes of the changes this one depends on. */
  readonly deps: readonly string[];
  /** Hex IDs of the other actors the change refers to (§11.1: each must be known to the document). */
  readonly otherActors: readonly string[];
}

/**
 * Checks that `bytes` is exactly one valid Automerge change (§11, §12) and
 * returns it decoded. Rejects with PROFILE_INVALID / INVALID_AUTOMERGE_BYTES: a chunk that is not a
 * change (a document chunk is a full save, §13), bytes Automerge cannot
 * parse, trailing bytes such as a second concatenated change, and a
 * checksum that does not match the change hash. Automerge JS 3.5.0 parses
 * a change without verifying its checksum, so the check is done here.
 */
export function checkChange(bytes: Uint8Array): CheckedChange {
  const type = chunkType(bytes, "the change");
  if (type === CHUNK_COMPRESSED_CHANGE)
    reject("a compressed Automerge change (chunk type 2): a change is uncompressed (§11)");
  if (type !== CHUNK_CHANGE) reject(`chunk type ${type} is not an Automerge change (§11)`);
  // §11.1: what the change expands to and its structure, before Automerge decodes it.
  const expansion = checkChangeExpansion(bytes);
  // §11.3: the canonical encoding, by the format's properties, still before the engine.
  const parsed = checkCanonicalChange(bytes);
  let decoded: A.DecodedChange;
  try {
    decoded = A.decodeChange(bytes);
  } catch (e) {
    return reject(`invalid Automerge change bytes (§11): ${(e as Error).message}`);
  }
  if (toHex(bytes.subarray(4, 8)) !== decoded.hash.slice(0, 8))
    reject("the Automerge change checksum does not match its hash (§11)");
  const checked: CheckedChange = Object.freeze({
    bytes: Uint8Array.from(bytes),
    hash: decoded.hash,
    actor: decoded.actor,
    seq: decoded.seq,
    deps: Object.freeze([...decoded.deps]),
    otherActors: expansion.otherActors,
  });
  DECODED.set(checked, decoded);
  PARSED.set(checked, parsed);
  return checked;
}

/** The operations checkChange read from the bytes (§11.3), for the references of §11.4. */
const PARSED = new WeakMap<CheckedChange, ParsedChange>();

/** The change as its canonical bytes give it (§11.3), reusing the walk of checkChange. */
export function parsedOf(change: CheckedChange): ParsedChange {
  let p = PARSED.get(change);
  if (p === undefined) {
    p = checkCanonicalChange(change.bytes);
    PARSED.set(change, p);
  }
  return p;
}

/** The decoded form checkChange made, kept for the change's lifetime (decoding is not cheap). */
const DECODED = new WeakMap<CheckedChange, A.DecodedChange>();

/** The decoded change, reusing the decode of checkChange when there was one. */
export function decodedOf(change: CheckedChange): A.DecodedChange {
  return DECODED.get(change) ?? A.decodeChange(change.bytes);
}

/**
 * Checks that `bytes` starts as an Automerge full save (a document chunk,
 * §13). Whether the whole image loads, checksums included, is decided by
 * Automerge's load.
 */
export function checkSaveHeader(bytes: Uint8Array): void {
  const type = chunkType(bytes, "the Snapshot image");
  if (type !== CHUNK_DOCUMENT)
    reject(`chunk type ${type} is not an Automerge document (full save, §13)`);
}

/** §11: the Data Unit plaintext [1, change] of one checked Automerge change. */
export function frameChange(change: Uint8Array): Uint8Array {
  checkChange(change);
  return frameProfilePayload(change);
}

/** §11: the one Automerge change a Data Unit plaintext carries, checked. Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES. */
export function unframeChange(plaintext: Uint8Array): CheckedChange {
  return checkChange(unframeProfilePayload(plaintext));
}

/** §13: the Snapshot plaintext [1, save] of an Automerge full save. */
export function frameSnapshot(save: Uint8Array): Uint8Array {
  checkSaveHeader(save);
  return frameProfilePayload(save);
}

/** §13: the Automerge full save a Snapshot plaintext carries (header checked). Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES. */
export function unframeSnapshot(plaintext: Uint8Array): Uint8Array {
  const save = unframeProfilePayload(plaintext);
  checkSaveHeader(save);
  return save;
}

/** §11, §13: the only framing version. */
export const FRAMING_VERSION = 1;

/** The deterministic CBOR head of a byte string of `length` bytes (major type 2, shortest form). */
function bstrHead(length: number): number[] {
  if (length < 24) return [0x40 | length];
  if (length < 0x100) return [0x58, length];
  if (length < 0x10000) return [0x59, length >> 8, length & 0xff];
  if (length <= 0xffffffff)
    return [
      0x5a,
      (length >>> 24) & 0xff,
      (length >>> 16) & 0xff,
      (length >>> 8) & 0xff,
      length & 0xff,
    ];
  throw new LfcpError("OUT_OF_RANGE", "the framed bytes are too long");
}

/**
 * Deterministic CBOR of [1, bstr] (§11 shared-objects-change, §13
 * shared-objects-snapshot): the profile plaintext of a Data Unit (one
 * Automerge change) or a Snapshot (one Automerge full save). The bytes are
 * framed as given; checking that they are a valid Automerge change or save
 * is the Automerge binding (LFCP-031).
 */
export function frameProfilePayload(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array)) throw new LfcpError("INVALID_LENGTH", "framing takes bytes");
  const head = bstrHead(bytes.length);
  const out = new Uint8Array(2 + head.length + bytes.length);
  out.set([0x82, FRAMING_VERSION, ...head], 0);
  out.set(bytes, 2 + head.length);
  return out;
}

/**
 * The inner bytes of a framed profile plaintext. §11: a receiver MUST
 * reject plaintext that is not valid CBOR, not a two-element array, or
 * uses an unsupported framing version; this also requires the
 * deterministic encoding and no trailing bytes. Throws PROFILE_INVALID /
 * INVALID_AUTOMERGE_BYTES (§74.1).
 */
export function unframeProfilePayload(framed: Uint8Array): Uint8Array {
  const fail = (why: string): never => {
    throw new ProfileInvalidError("INVALID_AUTOMERGE_BYTES", `invalid profile framing: ${why}`);
  };
  if (!(framed instanceof Uint8Array) || framed.length < 3) return fail("too short");
  if (framed[0] !== 0x82) return fail("not a two-element array");
  if (framed[1] !== FRAMING_VERSION) return fail("unsupported framing version");
  const first = framed[2] as number;
  if (first >> 5 !== 2) return fail("the second element is not a byte string");
  const info = first & 0x1f;
  let length: number;
  let offset: number;
  const at = (i: number) => framed[i] as number;
  if (info < 24) [length, offset] = [info, 3];
  else if (info === 24) [length, offset] = [at(3), 4];
  else if (info === 25) [length, offset] = [(at(3) << 8) | at(4), 5];
  else if (info === 26)
    [length, offset] = [((at(3) << 24) >>> 0) + (at(4) << 16) + (at(5) << 8) + at(6), 7];
  else return fail("unsupported byte string length");
  if (offset > framed.length) return fail("truncated");
  const bytes = framed.subarray(offset);
  if (bytes.length !== length) return fail(bytes.length < length ? "truncated" : "trailing bytes");
  const canonical = bstrHead(length);
  if (canonical.length !== offset - 2) return fail("non-shortest byte string length");
  return Uint8Array.from(bytes);
}
