import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  type PrincipalId,
  toHex,
} from "@openlfcp/core";
import type { ResourceDEK } from "@openlfcp/crypto";
import {
  ABILITY,
  ABILITY_NAMES,
  type ChainResult,
  type HaveVector,
  hasAbility,
  isGrantActive,
  KEY_EPOCH_REASON,
  type PrincipalDescriptor,
  parseKeyPackage,
  rotateEpoch,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
  verifyKeyPackage,
} from "@openlfcp/wire";

/**
 * Removing a member's access (LFCP-02-060, LFCP-WIRE-01 §17.3, §19, §25):
 * every active grant naming the member that the revoker may revoke is
 * revoked, which also deactivates the grants delegated from it (§17.2);
 * then, when the member has no read access left, the Data Epoch is rotated
 * with a fresh DEK (§19, reason "member revoked"), and the new DEK goes in
 * Key Packages to every remaining reader, so the member cannot read new
 * data. Every record is built on the validated head and checked by
 * extending the chain before anything is queued.
 */

type Linear = Extract<ChainResult, { kind: "linear" }>;

/** A grant naming the member that the revoker may not revoke: the member keeps access through it. */
export interface RemainingPath {
  readonly grantId: ControlRecordId;
  readonly issuer: PrincipalId;
  readonly abilities: readonly string[];
}

/** What a revocation writes, before it is queued. */
export interface RevocationPlan {
  /** The grants revoked, in record order. */
  readonly revoked: readonly ControlRecordId[];
  /** Grants delegated from them that the revocations deactivate (§17.2). */
  readonly deactivated: readonly ControlRecordId[];
  /** The signed Control Records in order: the revocations, then the Key Epoch if any. */
  readonly records: readonly { readonly recordId: ControlRecordId; readonly bytes: Uint8Array }[];
  /** The new epoch and its DEK, when the epoch is rotated. */
  readonly rotation: { readonly epoch: DataEpoch; readonly dek: ResourceDEK } | null;
  /** Sealed Key Packages of the new DEK, one per remaining reader. */
  readonly keyPackages: readonly Uint8Array[];
  /** The readers who receive them. */
  readonly recipients: readonly PrincipalId[];
  readonly remainingPaths: readonly RemainingPath[];
}

export type RevocationRefusal =
  /** The member is the Resource's owner: ownership is transferred, never revoked. */
  | "would-remove-owner"
  /** No active grant names the member. */
  | "not-member"
  /** The revoker may revoke none of the member's grants, or may not rotate the epoch. */
  | "not-authorized";

export class RevocationRefused extends Error {
  constructor(
    readonly reason: RevocationRefusal,
    message: string,
  ) {
    super(message);
    this.name = "RevocationRefused";
  }
}

const name = (a: bigint) => ABILITY_NAMES.get(a) ?? `${a}`;

/**
 * Plans the removal of `subject` by `revoker` on the validated chain
 * `view`. `frontier` is the closing epoch's accepted final frontier (the
 * local Have). With `rotate: false`, or when the member keeps read access
 * through a remaining path, the epoch is not rotated. Throws
 * RevocationRefused.
 */
export async function planRevocation(options: {
  readonly view: Linear;
  readonly revoker: Signer;
  readonly subject: PrincipalId;
  readonly frontier: HaveVector;
  readonly rotate?: boolean;
}): Promise<RevocationPlan> {
  const { view, revoker, subject } = options;
  const state0 = view.state;
  const R = state0.resourceId;
  if (bytesEqual(state0.owner.principalId, subject))
    throw new RevocationRefused("would-remove-owner", "the owner's access is not revoked (§17.3)");
  const grants = [...state0.grants.values()].filter(
    (g) => bytesEqual(g.subject, subject) && isGrantActive(state0, g.id),
  );
  if (grants.length === 0)
    throw new RevocationRefused("not-member", "no active grant names this Principal");

  let bytes = view.records.map((r) => r.signed.bytes);
  let running: Linear = view;
  const records: { recordId: ControlRecordId; bytes: Uint8Array }[] = [];
  const revoked: ControlRecordId[] = [];
  const remainingPaths: RemainingPath[] = [];
  for (const g of grants) {
    // Already inactive through an earlier revocation of its ancestor (§17.2).
    if (!isGrantActive(running.state, g.id)) continue;
    const signed = signControlRecord(
      { resourceId: R, controlSeq: running.state.seq + 1n, prevControlId: running.state.head },
      { type: "CAPABILITY_REVOKE", grantId: g.id },
      revoker,
    );
    const next = validateControlChain([...bytes, signed.bytes]);
    if (next.kind !== "linear") {
      remainingPaths.push(
        Object.freeze({
          grantId: g.id,
          issuer: g.issuer,
          abilities: Object.freeze(g.abilities.map(name)),
        }),
      );
      continue;
    }
    bytes = [...bytes, signed.bytes];
    running = next;
    records.push({ recordId: signed.recordId, bytes: signed.bytes });
    revoked.push(g.id);
  }
  if (revoked.length === 0)
    throw new RevocationRefused(
      "not-authorized",
      "the revoker may revoke none of this Principal's grants (§17.3)",
    );
  const revokedKeys = new Set(revoked.map((id) => toHex(id)));
  const deactivated = [...state0.grants.values()]
    .filter(
      (g) =>
        !revokedKeys.has(toHex(g.id)) &&
        isGrantActive(state0, g.id) &&
        !isGrantActive(running.state, g.id),
    )
    .map((g) => g.id);

  let rotation: RevocationPlan["rotation"] = null;
  const keyPackages: Uint8Array[] = [];
  const recipients: PrincipalId[] = [];
  const stillReads = hasAbility(running.state, subject, ABILITY.DATA_READ);
  if (options.rotate !== false && !stillReads) {
    const r = rotateEpoch(running.state, revoker, {
      reason: KEY_EPOCH_REASON.MEMBER_REVOKED,
      finalFrontier: options.frontier,
    });
    const next = validateControlChain([...bytes, r.bytes]);
    if (next.kind !== "linear")
      throw new RevocationRefused(
        "not-authorized",
        "the revoker may not rotate the Data Epoch (key/rotate, §19)",
      );
    running = next;
    records.push({ recordId: controlRecordId(r.recordId), bytes: r.bytes });
    rotation = Object.freeze({ epoch: r.epoch, dek: r.dek });
    // Every remaining reader but the revoker, who keeps the DEK it made.
    const readers: PrincipalDescriptor[] = [
      running.state.owner,
      ...[...running.state.principals.values()],
    ].filter(
      (d, i, all) =>
        all.findIndex((x) => bytesEqual(x.principalId, d.principalId)) === i &&
        !bytesEqual(d.principalId, revoker.descriptor.principalId) &&
        hasAbility(running.state, d.principalId, ABILITY.DATA_READ),
    );
    for (const recipient of readers) {
      const sealed = await sealKeyPackage({
        resourceId: R,
        epoch: r.epoch,
        controlHead: r.recordId,
        recipient,
        dek: r.dek,
        signer: revoker,
      });
      const check = verifyKeyPackage(running, parseKeyPackage(sealed.bytes));
      if (check.kind !== "authorized")
        throw new RevocationRefused(
          "not-authorized",
          `the revoker may not distribute the new key: ${check.message}`,
        );
      keyPackages.push(sealed.bytes);
      recipients.push(recipient.principalId);
    }
  }
  return Object.freeze({
    revoked: Object.freeze(revoked),
    deactivated: Object.freeze(deactivated),
    records: Object.freeze(records),
    rotation,
    keyPackages: Object.freeze(keyPackages),
    recipients: Object.freeze(recipients),
    remainingPaths: Object.freeze(remainingPaths),
  });
}
