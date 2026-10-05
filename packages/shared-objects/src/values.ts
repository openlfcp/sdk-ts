import {
  fromBase64url,
  ID32_LENGTH,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  toBase64url,
} from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";

/**
 * Value-level rules of SHARED-OBJECTS-PROFILE-01: Principal references,
 * Local Dates, timestamps, reverse-domain names, namespaced values, the
 * Automerge actor ID and the profile framing of Data Unit and Snapshot
 * plaintexts.
 */

/** §6: the profile identifier. */
export const PROFILE_ID = "org.openlfcp.shared-objects.v1";

/** A Principal reference (§27, §42): "p:" + unpadded base64url of the 32-byte Principal ID. */
export type PrincipalRef = string & { readonly __principalRef: true };

/** §27: the reference of a Principal ID. */
export function principalRef(id: PrincipalId): PrincipalRef {
  return `p:${toBase64url(principalId(id))}` as PrincipalRef;
}

/** True when `text` is a canonical Principal reference of exactly 32 bytes. */
export function isPrincipalRef(text: unknown): text is PrincipalRef {
  if (typeof text !== "string" || !text.startsWith("p:")) return false;
  try {
    return fromBase64url(text.slice(2)).length === ID32_LENGTH;
  } catch {
    return false;
  }
}

/** The Principal ID a reference names; throws INVALID_BASE64URL / INVALID_LENGTH otherwise. */
export function parsePrincipalRef(text: string): PrincipalId {
  if (!text.startsWith("p:"))
    throw new LfcpError("INVALID_BASE64URL", "a Principal reference starts with p:");
  return principalId(fromBase64url(text.slice(2)));
}

/** §35: a real Gregorian date YYYY-MM-DD (no time zone). */
export function isLocalDate(text: unknown): text is string {
  if (typeof text !== "string") return false;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (m === null) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return mo >= 1 && mo <= 12 && d >= 1 && d <= (days[mo - 1] as number);
}

/** §28: an RFC 3339 UTC timestamp ending in Z with a real date and time (second 60 for leap seconds). */
export function isUtcTimestamp(text: unknown): text is string {
  if (typeof text !== "string") return false;
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?Z$/.exec(text);
  return (
    m !== null &&
    isLocalDate(m[1]) &&
    Number(m[2]) <= 23 &&
    Number(m[3]) <= 59 &&
    Number(m[4]) <= 60
  );
}

const LABEL = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?";
const REVERSE_DOMAIN = new RegExp(`^${LABEL}(?:\\.${LABEL})+$`);
const NAMESPACED = new RegExp(`^x/${LABEL}(?:\\.${LABEL})+/[^/]+$`, "u");

/** §18 ABNF reverse-domain: at least two lowercase LDH labels without leading or trailing hyphen. */
export const isReverseDomain = (text: unknown): text is string =>
  typeof text === "string" && REVERSE_DOMAIN.test(text);

/** §33 ABNF namespaced-value: x/<reverse-domain>/<value>, value non-empty without "/". */
export const isNamespacedValue = (text: unknown): text is string =>
  typeof text === "string" && NAMESPACED.test(text);

const ACTOR_DOMAIN = Uint8Array.from("OPENLFCP-SHARED-OBJECTS-ACTOR-v1", (c) => c.charCodeAt(0));

/**
 * §8: the Automerge actor ID of `principal` editing `resource`:
 * SHA-256(ASCII("OPENLFCP-SHARED-OBJECTS-ACTOR-v1") || resource_id || principal_id),
 * from the raw 32-byte IDs.
 */
export function deriveActorId(resource: ResourceId, principal: PrincipalId): Uint8Array {
  for (const [what, id] of [
    ["the Resource ID", resource],
    ["the Principal ID", principal],
  ] as const) {
    if (!(id instanceof Uint8Array) || id.length !== ID32_LENGTH)
      throw new LfcpError("INVALID_LENGTH", `${what} must be the raw 32-byte ID`);
  }
  const input = new Uint8Array(ACTOR_DOMAIN.length + 2 * ID32_LENGTH);
  input.set(ACTOR_DOMAIN, 0);
  input.set(resource, ACTOR_DOMAIN.length);
  input.set(principal, ACTOR_DOMAIN.length + ID32_LENGTH);
  return sha256(input);
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
 * deterministic encoding and no trailing bytes. Throws PROFILE_FRAMING.
 */
export function unframeProfilePayload(framed: Uint8Array): Uint8Array {
  const fail = (why: string): never => {
    throw new LfcpError("PROFILE_FRAMING", `invalid profile framing: ${why}`);
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
