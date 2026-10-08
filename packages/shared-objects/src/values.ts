import {
  fromBase64url,
  ID32_LENGTH,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  toBase64url,
} from "@openlfcp/core";
import { deriveDomainActorId } from "./admission/actor.js";

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

/** §8: the actor domain of this profile. */
export const ACTOR_DOMAIN = "OPENLFCP-SHARED-OBJECTS-ACTOR-v1";

/**
 * §8: the Automerge actor ID of `principal` editing `resource`:
 * SHA-256(ASCII("OPENLFCP-SHARED-OBJECTS-ACTOR-v1") || resource_id || principal_id),
 * from the raw 32-byte IDs.
 */
export function deriveActorId(resource: ResourceId, principal: PrincipalId): Uint8Array {
  return deriveDomainActorId(ACTOR_DOMAIN, resource, principal);
}

// §11, §13: the profile framing [1, bytes] is part of the admission module
// both profiles share (./admission/framing.ts); re-exported here unchanged.
export {
  FRAMING_VERSION,
  frameProfilePayload,
  unframeProfilePayload,
} from "./admission/framing.js";
