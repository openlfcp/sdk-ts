import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type PrincipalId,
  toHex,
} from "@openlfcp/core";
import { ABILITY, hasAbility } from "./capability.js";
import type { ChainResult } from "./chain.js";

type Linear = Extract<ChainResult, { kind: "linear" }>;

/** The end of the Control Chain prefix a revoked reader may still read (W §41). */
export interface RevokedReaderPrefix {
  /** Position of the revoking record in the chain (Genesis is 0). */
  readonly index: number;
  /** The first record that revoked the Principal: the prefix's only Control Head. */
  readonly recordId: ControlRecordId;
  readonly reason: bigint;
}

/**
 * W §41 "Control read for a revoked reader": a Principal `p` that no longer
 * holds `data/read` at the accepted head may read the Control Chain prefix
 * through the first `DEVICE_REVOKE {root, p, ...}` with `root =
 * devices[p].root`, when `p` is registered and held `data/read` at the head
 * immediately before that record. Undefined otherwise: an unbound,
 * intermediate-only or out-of-scope device, a device whose mask never
 * conferred `data/read`, a device whose root lost standing without a
 * revocation, and a current reader get nothing from this rule. A consumed
 * pairing device (reason 3) is covered like any revoked reader. This is
 * what lets a revoked device prove its revocation (IDENTITY-PROFILE-01
 * §8.6); a server serves it, a client verifies it the same way.
 */
export function revokedReaderPrefix(
  chain: Linear,
  p: PrincipalId,
): RevokedReaderPrefix | undefined {
  if (hasAbility(chain.state, p, ABILITY.DATA_READ)) return undefined;
  const d = chain.state.devices.get(toHex(p));
  if (d === undefined || !d.registered) return undefined;
  for (let i = 1; i < chain.records.length; i++) {
    const r = chain.records[i];
    if (r?.body.type !== "DEVICE_REVOKE") continue;
    if (!bytesEqual(r.body.device, p) || !bytesEqual(r.body.root, d.root)) continue;
    const before = chain.stateAt(chain.records[i - 1]?.signed.id as Uint8Array);
    if (before === undefined || !hasAbility(before, p, ABILITY.DATA_READ)) return undefined;
    return Object.freeze({
      index: i,
      recordId: controlRecordId(r.signed.id),
      reason: r.body.reason,
    });
  }
  return undefined;
}
