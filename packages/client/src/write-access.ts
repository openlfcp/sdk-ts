import { bytesEqual, type ControlRecordId, type PrincipalId } from "@openlfcp/core";
import { ABILITY, type ChainResult, hasAbility } from "@openlfcp/wire";

/**
 * Write access (SDK-SECTIONS-INTEGRATION-01 §6): whether this client may
 * commit to a Resource, decided from the validated Control state only.
 */

/** §6: why writing is not allowed. */
export type WriteDeniedReason =
  | "not-member"
  | "read-only"
  | "key-unavailable"
  | "revoked"
  | "unknown";

/** §6: the answer of canWrite. `controlHead` and `verifiedAt` are its freshness. */
export interface WriteAccess {
  readonly allowed: boolean;
  /** Why not, when not allowed; null when allowed. */
  readonly reason: WriteDeniedReason | null;
  /** The Control Head the decision was validated at; null without a validated chain. */
  readonly controlHead: ControlRecordId | null;
  /** The local time (ms since the epoch) of that validation; null without one. */
  readonly verifiedAt: number | null;
}

/** §3.6: a batch submitted while writing is not allowed. A local SDK error; nothing is written. */
export class NotWritableError extends Error {
  readonly code = "NOT_WRITABLE";

  constructor(readonly access: WriteAccess) {
    super(`writing is not allowed: ${access.reason ?? "unknown"} (SDK-SECTIONS-INTEGRATION-01 §6)`);
    this.name = "NotWritableError";
  }
}

/** The answer without a validated chain: unknown, never a default (§2). */
export const UNKNOWN_ACCESS: WriteAccess = Object.freeze({
  allowed: false,
  reason: "unknown",
  controlHead: null,
  verifiedAt: null,
});

/**
 * Decides write access for `principal` from a validated chain: `data/write`
 * (LFCP-WIRE-01 §17) and the current epoch's DEK are both needed. Without
 * `data/write`, a principal holding `data/read` is read-only, one whose
 * every grant was revoked is revoked, and anyone else is not a member.
 */
export function writeAccess(
  chain: ChainResult | undefined | null,
  principal: PrincipalId,
  hasCurrentDek: boolean,
  verifiedAt: number,
): WriteAccess {
  if (chain?.kind !== "linear") return UNKNOWN_ACCESS;
  const { state } = chain;
  const at = { controlHead: state.head, verifiedAt };
  const denied = (reason: WriteDeniedReason): WriteAccess =>
    Object.freeze({ allowed: false, reason, ...at });
  if (!hasAbility(state, principal, ABILITY.DATA_WRITE)) {
    if (hasAbility(state, principal, ABILITY.DATA_READ)) return denied("read-only");
    const grants = [...state.grants.values()].filter((g) => bytesEqual(g.subject, principal));
    return denied(grants.some((g) => g.revokedBy !== null) ? "revoked" : "not-member");
  }
  if (!hasCurrentDek) return denied("key-unavailable");
  return Object.freeze({ allowed: true, reason: null, ...at });
}
