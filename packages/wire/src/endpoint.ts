import type { CborValue } from "./cbor/index.js";
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
 * Structure only. The URL scheme rule (`wss://` except on loopback) and the
 * reserved flag bits are connection policy, checked where endpoints are used
 * (Genesis and Route Update bodies, LFCP-019; connections, LFCP-027).
 */
export function endpointFromCbor(value: CborValue): Endpoint {
  const f = new Fields(value, "endpoint", [0, 1], [2]);
  const url = f.text(0);
  const priority = f.uint(1);
  return Object.freeze(f.has(2) ? { url, priority, flags: f.uint(2) } : { url, priority });
}
