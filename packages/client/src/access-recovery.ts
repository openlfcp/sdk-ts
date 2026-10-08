import { bytesEqual, type PrincipalId } from "@openlfcp/core";
import { ABILITY, type ControlRecord, type ControlState, hasAbility } from "@openlfcp/wire";

/**
 * Recovering access after a server restore (LFCP-02-106; design:
 * `.github: docs/devel/design/member-recovery-after-restore.md`).
 *
 * A restored server may have lost the Control Records that grant this
 * session's Principal `data/read`, and then refuses RESOURCE_OPEN with
 * AUTHORIZATION_FAILED. A member whose own validated chain grants it
 * `data/read` re-supplies the records the server lacks with CONTROL_PUT,
 * which needs no read access (§47, §84): the server checks each record by
 * its issuer. It learns the server's head from CONTROL_HEAD_MISMATCH,
 * pushes the records above it oldest first, and opens again once.
 *
 * Security: the member uploads only records it holds, each signed by its
 * issuer, and learns only the server's head ID (any session learns it from
 * a mismatch). A chain that does not grant the member access sends nothing;
 * a server head the member does not know (a revocation it has not seen, a
 * fork) stops the recovery. Attempts are bounded.
 *
 * These are the pure decisions; SyncClient sends the requests.
 */

/** What to do next. */
export type RecoveryStep =
  /** CONTROL_PUT of `records[index]`, expecting `records[index - 1]`. */
  | { readonly kind: "push"; readonly index: number }
  /** The server holds the whole chain now: RESOURCE_OPEN again, once. */
  | { readonly kind: "reopen" }
  /** No recovery: the refusal stands. */
  | { readonly kind: "final"; readonly reason: RecoveryEnd };

export type RecoveryEnd =
  /** The local chain does not grant this Principal data/read: never tried. */
  | "not-granted"
  /** The server holds our head: the refusal is not caused by a loss. */
  | "server-current"
  /** The server's head is not in our chain: a record we have not seen, or a fork. */
  | "unknown-head"
  /** The server refused a record for good, or the transient bound was reached. */
  | "refused";

/** Transient refusals of a recovery CONTROL_PUT, retried with backoff a bounded number of times. */
export const RECOVERY_TRANSIENT_CODES: ReadonlySet<string> = new Set([
  "RATE_LIMITED",
  "INTERNAL_ERROR",
]);

/** How many transient refusals a recovery tolerates before it ends. */
export const RECOVERY_TRANSIENT_ATTEMPTS = 3;

/**
 * The first step after RESOURCE_OPEN was refused with AUTHORIZATION_FAILED:
 * push our head (the server's answer tells where its chain ends), or not
 * at all when our chain does not grant `principal` data/read or has nothing
 * above the Genesis to push.
 */
export function startRecovery(
  state: ControlState,
  records: readonly ControlRecord[],
  principal: PrincipalId,
): RecoveryStep {
  if (!hasAbility(state, principal, ABILITY.DATA_READ)) return final("not-granted");
  if (records.length < 2) return final("server-current");
  return { kind: "push", index: records.length - 1 };
}

/** The next step after the server committed `records[index]`. */
export function afterAccepted(records: readonly ControlRecord[], index: number): RecoveryStep {
  return index >= records.length - 1 ? { kind: "reopen" } : { kind: "push", index: index + 1 };
}

/**
 * The next step after CONTROL_HEAD_MISMATCH naming the server's head
 * `head`: push the record above it; open again once when the server holds
 * our head (another holder re-supplied it meanwhile; if the refusal is not
 * caused by a loss, the second AUTHORIZATION_FAILED is final); stop at a
 * head we do not know.
 */
export function afterMismatch(records: readonly ControlRecord[], head: unknown): RecoveryStep {
  if (!(head instanceof Uint8Array)) return final("refused");
  const at = records.findIndex((r) => bytesEqual(r.signed.id, head));
  if (at < 0) return final("unknown-head");
  if (at === records.length - 1) return { kind: "reopen" };
  return { kind: "push", index: at + 1 };
}

const final = (reason: RecoveryEnd): RecoveryStep => ({ kind: "final", reason });
