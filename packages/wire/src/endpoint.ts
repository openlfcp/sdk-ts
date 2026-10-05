import { LfcpError } from "@openlfcp/core";
import { type CborValue, cborMap } from "./cbor/index.js";
import { Fields } from "./fields.js";

/** A sync endpoint (LFCP-WIRE-01 §16). */
export interface Endpoint {
  readonly url: string;
  /** Lower is preferred. */
  readonly priority: bigint;
  /** §16 flag bits; undefined when the CBOR omits key 2. */
  readonly flags?: bigint;
}

/**
 * Decodes an `endpoint` map: exactly keys 0 (tstr) and 1 (uint), optional
 * 2 (uint). A violation is INVALID_STRUCTURE (MALFORMED_MESSAGE on the wire).
 *
 * Structure only. Reserved flag bits are kept: "A writer sets reserved bits
 * to 0; a receiver ignores them" (§16). The receiver's URL scheme rule is
 * checkReceivedUrl, applied by the Control Record decoders.
 */
export function endpointFromCbor(value: CborValue): Endpoint {
  const f = new Fields(value, "endpoint", [0, 1], [2]);
  const url = f.text(0);
  const priority = f.uint(1);
  return Object.freeze(f.has(2) ? { url, priority, flags: f.uint(2) } : { url, priority });
}

/** The §16 flag bits LFCP-WIRE-01 defines (0-5); all other bits are reserved. */
export const ENDPOINT_FLAGS = Object.freeze({
  DATA_PLANE_STORAGE: 1n << 0n,
  CONTROL_PLANE_STORAGE: 1n << 1n,
  SNAPSHOTS: 1n << 2n,
  PRESENCE: 1n << 3n,
  PREFERRED_FOR_READS: 1n << 4n,
  PREFERRED_FOR_WRITES: 1n << 5n,
});
const DEFINED_FLAGS = 0b11_1111n;
const UINT64_MAX = 2n ** 64n - 1n;

function refuse(why: string): never {
  throw new LfcpError("INVALID_STRUCTURE", `refusing to write an endpoint: ${why}`);
}

/**
 * §16, receiver side: "A receiver MUST reject a record carrying such a URL
 * [an endpoint or Control Coordinator URL in a Control Record] with any
 * scheme other than ws or wss with MALFORMED_MESSAGE." Only the scheme is
 * checked (case-insensitively, RFC 3986 §3.1); the loopback rule is the
 * sender's. Throws INVALID_STRUCTURE.
 */
export function checkReceivedUrl(url: string): void {
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(url)?.[1]?.toLowerCase();
  if (scheme !== "ws" && scheme !== "wss")
    throw new LfcpError(
      "INVALID_STRUCTURE",
      `an endpoint or coordinator URL must use ws or wss, not ${scheme ?? "no scheme"} (§16)`,
    );
}

/**
 * Checks a URL an LFCP writer puts in an endpoint or a coordinator field
 * (§16: "A sender uses wss://, except ws:// for a loopback address").
 *
 * Accepted: an absolute URI (RFC 3986 §4.3: no fragment) with scheme wss,
 * or ws on a loopback host (localhost, 127.0.0.0/8, [::1]).
 */
export function checkWriterUrl(url: string): void {
  if (typeof url !== "string") refuse("the URL must be a text string");
  const control = [...url].some((ch) => {
    const c = ch.codePointAt(0) as number;
    return c < 0x20 || c === 0x7f;
  });
  if (control || /\s/.test(url)) refuse("the URL contains whitespace or control characters");
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]+)([^#]*)$/.exec(url);
  if (m === null) refuse("not an absolute URL with an authority and no fragment");
  const scheme = (m[1] as string).toLowerCase();
  const authority = m[2] as string;
  if (authority.includes("@")) refuse("user information is not allowed in the URL");
  const host = (/^(\[[^\]]*\]|[^:]*)(:\d*)?$/.exec(authority)?.[1] ?? "").toLowerCase();
  if (host === "") refuse("the URL has no host");
  const loopback =
    host === "localhost" || host === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (scheme === "wss") return;
  if (scheme === "ws" && loopback) return;
  refuse(
    scheme === "ws"
      ? "ws:// is only for loopback hosts; use wss://"
      : `scheme ${scheme} is not wss`,
  );
}

/**
 * Encodes an endpoint for a record this SDK writes. Writer rules: the URL
 * passes checkWriterUrl, the priority and flags are uint64, and no
 * reserved flag bit (6 and up) is set.
 */
export function endpointToCbor(endpoint: Endpoint): CborValue {
  checkWriterUrl(endpoint.url);
  const uint = (what: string, n: unknown): bigint => {
    if (typeof n !== "bigint" || n < 0n || n > UINT64_MAX)
      refuse(`${what} must be a uint64 bigint`);
    return n;
  };
  const priority = uint("the priority", endpoint.priority);
  if (endpoint.flags === undefined)
    return cborMap([
      [0, endpoint.url],
      [1, priority],
    ]);
  const flags = uint("the flags", endpoint.flags);
  if ((flags & ~DEFINED_FLAGS) !== 0n) refuse("reserved flag bits (6 and up) must not be set");
  return cborMap([
    [0, endpoint.url],
    [1, priority],
    [2, flags],
  ]);
}
