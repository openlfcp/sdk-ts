import { bytesEqual, type ControlRecordId, type PrincipalId } from "@openlfcp/core";
import {
  ABILITY,
  ABILITY_NAMES,
  abilitiesOf,
  type ChainResult,
  type ControlBody,
  hasAbility,
  isGrantActive,
} from "@openlfcp/wire";

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
  | "unknown"
  /**
   * LFCP-02-115: the server refuses this client the Resource
   * (AUTHORIZATION_FAILED on RESOURCE_OPEN) although the local chain grants
   * it. The server does not say why: a revocation this client has not seen,
   * or a server that lost state and could not be recovered (106).
   */
  | "server-refused";

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
 * every grant is inactive (revoked, or delegated from a revoked one, §17.2)
 * is revoked, and anyone else is not a member.
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
    return denied(grants.some((g) => !isGrantActive(state, g.id)) ? "revoked" : "not-member");
  }
  if (!hasCurrentDek) return denied("key-unavailable");
  return Object.freeze({ allowed: true, reason: null, ...at });
}

/** One grant path to this principal (§17.2): an active grant naming it. */
export interface GrantPath {
  readonly grantId: ControlRecordId;
  readonly source: "grant" | "claim";
  /** The ability names it lists. */
  readonly abilities: readonly string[];
  /** It is delegated from another grant (§17.2): active while that one is. */
  readonly delegated: boolean;
}

/** An invitation this principal issued (§18.1): not access of anyone until claimed. */
export interface IssuedInvitation {
  readonly grantId: ControlRecordId;
  readonly claimLimit: bigint;
  readonly claimsUsed: bigint;
}

/** A Control Record of this principal sent and not committed yet (SI14): pending, never done. */
export interface PendingControl {
  readonly recordId: ControlRecordId;
  readonly type: ControlBody["type"];
}

/**
 * LFCP-02-027: write access with the evidence around it. `abilities` and
 * `paths` are active access at `controlHead`; invitations issued, our own
 * pending Control Records and an unsettled invitation claim are kept
 * apart and never count as access.
 */
export interface AccessState extends WriteAccess {
  /** The Control sequence of `controlHead`; null without a validated chain. */
  readonly controlSeq: bigint | null;
  /** The highest Control sequence a server reported in this session; null when none did. */
  readonly serverControlSeq: bigint | null;
  /**
   * Whether the validated chain reaches what the server reported: false
   * while it is behind (a stale Control view: the access may already have
   * changed), null when no server reported a head in this session.
   */
  readonly current: boolean | null;
  readonly owner: boolean;
  /** Effective ability names (§17.1), over every active grant path. */
  readonly abilities: readonly string[];
  readonly paths: readonly GrantPath[];
  readonly invitations: readonly IssuedInvitation[];
  readonly pendingControl: readonly PendingControl[];
  /** An invitation claim of this principal is journaled and not settled (LFCP-02-110). */
  readonly pendingClaim: boolean;
  /**
   * LFCP-02-115: the server refuses this client the Resource in this
   * session; then `allowed` is false with reason "server-refused" and
   * `current` is false, whatever the local chain says.
   */
  readonly serverRefusal: ServerRefusal | null;
}

/** LFCP-02-115: the server's refusal of the Resource in this session, as far as it is known. */
export interface ServerRefusal {
  /** The §62 code, AUTHORIZATION_FAILED. */
  readonly code: string;
  /**
   * How the access recovery (LFCP-02-106) ended, when it ran: "unknown-head"
   * (the server holds Control Records this client has not seen), "refused",
   * "still-refused", "not-granted", "server-current"; null when it did not run.
   */
  readonly recovery: string | null;
}

/** The evidence of `accessState` the chain does not hold. */
export interface AccessContext {
  /** The server refuses the Resource in this session (LFCP-02-115). */
  readonly serverRefusal?: ServerRefusal | null;
  readonly serverControlSeq: bigint | null;
  readonly pendingControl: readonly PendingControl[];
  readonly pendingClaim: boolean;
}

/** AccessState from a validated chain (see writeAccess) and the context around it. */
export function accessState(
  chain: ChainResult | undefined | null,
  principal: PrincipalId,
  hasCurrentDek: boolean,
  verifiedAt: number,
  context: AccessContext,
): AccessState {
  const write = writeAccess(chain, principal, hasCurrentDek, verifiedAt);
  const state = chain?.kind === "linear" ? chain.state : undefined;
  const controlSeq = state?.seq ?? null;
  const server = context.serverControlSeq;
  const name = (a: bigint) => ABILITY_NAMES.get(a) ?? `${a}`;
  const grants = state === undefined ? [] : [...state.grants.values()];
  const refusal = context.serverRefusal ?? null;
  return Object.freeze({
    ...write,
    ...(refusal === null ? {} : { allowed: false, reason: "server-refused" as const }),
    controlSeq,
    serverControlSeq: server,
    current:
      refusal !== null
        ? false
        : server === null || controlSeq === null
          ? null
          : controlSeq >= server,
    owner: state !== undefined && bytesEqual(state.owner.principalId, principal),
    abilities: Object.freeze(state === undefined ? [] : abilitiesOf(state, principal).map(name)),
    paths: Object.freeze(
      grants
        .filter(
          (g) =>
            state !== undefined && bytesEqual(g.subject, principal) && isGrantActive(state, g.id),
        )
        .map((g) =>
          Object.freeze({
            grantId: g.id,
            source: g.source,
            abilities: Object.freeze(g.abilities.map(name)),
            delegated: g.parentGrantId !== null,
          }),
        ),
    ),
    invitations: Object.freeze(
      grants
        .filter(
          (g) =>
            state !== undefined &&
            g.claimLimit !== null &&
            bytesEqual(g.issuer, principal) &&
            isGrantActive(state, g.id),
        )
        .map((g) =>
          Object.freeze({
            grantId: g.id,
            claimLimit: g.claimLimit as bigint,
            claimsUsed: g.claimsUsed,
          }),
        ),
    ),
    pendingControl: Object.freeze([...context.pendingControl]),
    pendingClaim: context.pendingClaim,
    serverRefusal: refusal === null ? null : Object.freeze({ ...refusal }),
  });
}
