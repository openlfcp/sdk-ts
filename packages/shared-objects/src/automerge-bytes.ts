import * as A from "@automerge/automerge";
import { LfcpError, toHex } from "@openlfcp/core";
import { frameProfilePayload, unframeProfilePayload } from "./values.js";

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

const reject = (why: string): never => {
  throw new LfcpError("PROFILE_FRAMING", why);
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
}

/**
 * Checks that `bytes` is exactly one valid Automerge change (§11, §12) and
 * returns it decoded. Rejects with PROFILE_FRAMING: a chunk that is not a
 * change (a document chunk is a full save, §13), bytes Automerge cannot
 * parse, trailing bytes such as a second concatenated change, and a
 * checksum that does not match the change hash. Automerge JS 3.5.0 parses
 * a change without verifying its checksum, so the check is done here.
 */
export function checkChange(bytes: Uint8Array): CheckedChange {
  const type = chunkType(bytes, "the change");
  if (type !== CHUNK_CHANGE && type !== CHUNK_COMPRESSED_CHANGE)
    reject(`chunk type ${type} is not an Automerge change (§11)`);
  let decoded: A.DecodedChange;
  try {
    decoded = A.decodeChange(bytes);
  } catch (e) {
    return reject(`invalid Automerge change bytes (§11): ${(e as Error).message}`);
  }
  if (toHex(bytes.subarray(4, 8)) !== decoded.hash.slice(0, 8))
    reject("the Automerge change checksum does not match its hash (§11)");
  return Object.freeze({
    bytes: Uint8Array.from(bytes),
    hash: decoded.hash,
    actor: decoded.actor,
    seq: decoded.seq,
    deps: Object.freeze([...decoded.deps]),
  });
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

/** §11: the one Automerge change a Data Unit plaintext carries, checked. Throws PROFILE_FRAMING. */
export function unframeChange(plaintext: Uint8Array): CheckedChange {
  return checkChange(unframeProfilePayload(plaintext));
}

/** §13: the Snapshot plaintext [1, save] of an Automerge full save. */
export function frameSnapshot(save: Uint8Array): Uint8Array {
  checkSaveHeader(save);
  return frameProfilePayload(save);
}

/** §13: the Automerge full save a Snapshot plaintext carries (header checked). Throws PROFILE_FRAMING. */
export function unframeSnapshot(plaintext: Uint8Array): Uint8Array {
  const save = unframeProfilePayload(plaintext);
  checkSaveHeader(save);
  return save;
}
