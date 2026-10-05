import { LfcpError } from "./errors.js";

/**
 * Shared Object ID (SHARED-OBJECTS-PROFILE-01 §19): a UUIDv7 (RFC 9562) in its
 * canonical lowercase hyphenated string form.
 *
 * Object IDs identify objects; they do not order them. The UUIDv7 timestamp
 * and lexical order are NOT LFCP causality, conflict precedence or
 * authorization order, so this module deliberately offers no comparison,
 * sorting or timestamp extraction.
 */
declare const brand: unique symbol;
export type ObjectId = string & { readonly [brand]: "ObjectId" };

// Lowercase, standard hyphen positions, version 7, variant bits 10.
const UUIDV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** True when `text` is a canonical UUIDv7 Object ID. */
export function isObjectId(text: string): text is ObjectId {
  return UUIDV7.test(text);
}

/** Returns `text` as an ObjectId, or throws `INVALID_UUIDV7`. Non-canonical forms (e.g. upper case) are rejected, not normalized. */
export function parseObjectId(text: string): ObjectId {
  if (!isObjectId(text)) throw new LfcpError("INVALID_UUIDV7", "not a canonical lowercase UUIDv7");
  return text;
}

/** The canonical string form (Object IDs are stored canonically, so this is the value itself). */
export function formatObjectId(id: ObjectId): string {
  return id;
}

export interface GenerateObjectIdOptions {
  /** Unix time in milliseconds for the 48-bit timestamp; defaults to Date.now(). */
  readonly now?: number;
  /** Source of 10 random bytes; defaults to globalThis.crypto.getRandomValues. */
  readonly random?: (length: number) => Uint8Array;
}

function secureRandom(length: number): Uint8Array {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (typeof c?.getRandomValues !== "function") {
    throw new LfcpError("NO_SECURE_RANDOM", "globalThis.crypto.getRandomValues is not available");
  }
  return c.getRandomValues(new Uint8Array(length));
}

/**
 * Generates a new UUIDv7 Object ID (RFC 9562 §5.7): 48-bit Unix millisecond
 * timestamp, version 7, 12 random bits, variant 10, 62 random bits. No
 * within-millisecond counter is kept.
 */
export function generateObjectId(options: GenerateObjectIdOptions = {}): ObjectId {
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(now) || now < 0 || now > 0xffff_ffff_ffff) {
    throw new LfcpError("INVALID_UUIDV7", "timestamp must be an integer in [0, 2^48)");
  }
  const rnd = (options.random ?? secureRandom)(10);
  if (rnd.length !== 10)
    throw new LfcpError("INVALID_LENGTH", "random source must return 10 bytes");
  const b = new Uint8Array(16);
  let t = now;
  for (let i = 5; i >= 0; i -= 1) {
    b[i] = t % 256;
    t = Math.floor(t / 256);
  }
  b.set(rnd, 6);
  b[6] = 0x70 | ((b[6] as number) & 0x0f);
  b[8] = 0x80 | ((b[8] as number) & 0x3f);
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}` as ObjectId;
}
