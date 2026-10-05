import { bytesEqual, type DataEpoch, type Hash32, LfcpError } from "@openlfcp/core";
import { dekCommitment, type ResourceDEK } from "@openlfcp/crypto";
import type { SnapshotSequenceGuard, SnapshotSequenceReservation } from "@openlfcp/storage";
import {
  ABILITY,
  beyondCutoff,
  type ControlView,
  type DataProfileCodec,
  hasAbility,
  type LiveHaveEntry,
  normalizeLiveHaves,
  type Signer,
  sealSnapshot,
} from "@openlfcp/wire";

/**
 * Publishing an encrypted, signed Snapshot (LFCP-WIRE-01 §29). The Data
 * Profile's Snapshot codec turns the application state into plaintext;
 * LFCP encrypts and signs it. Only the opaque bytes are ever sent.
 */

export interface CreateSnapshotOptions<T> {
  readonly view: ControlView;
  /** The Control Head the Snapshot is authorized at (usually the latest one). */
  readonly controlHead: Uint8Array;
  readonly publisher: Signer;
  /** The DEK of the current Data Epoch at `controlHead`. */
  readonly dek: ResourceDEK;
  /** The only source of Snapshot Sequences (§29): durable in production (LFCP-034, LFCP-035). */
  readonly sequences: SnapshotSequenceReservation;
  readonly guard?: SnapshotSequenceGuard;
  /** The Data Plane holdings the Snapshot includes; normalized and canonicalized here (§28.2). */
  readonly frontier: readonly LiveHaveEntry[];
  /** The Data Profile's Snapshot codec. */
  readonly profile: DataProfileCodec<T>;
  readonly value: T;
}

export interface CreatedSnapshot {
  /** The exact signed bytes: opaque, the only form sent to servers and peers. */
  readonly bytes: Uint8Array;
  readonly snapshotId: Hash32;
  readonly seq: bigint;
  readonly epoch: DataEpoch;
}

/**
 * Creates a Snapshot. Before a sequence is reserved, it checks the head,
 * the profile, snapshot/publish at the head (§29.2), the DEK against the
 * head's current epoch, and that a closed epoch's Snapshot covers nothing
 * beyond its final frontier (§29, G-EP4; refused locally with
 * INVALID_STRUCTURE, the receiver's code is STALE_DATA_EPOCH). The frontier
 * is normalized into canonical form before it is encrypted and signed.
 */
export async function createSnapshot<T>(
  options: CreateSnapshotOptions<T>,
): Promise<CreatedSnapshot> {
  const atHead = options.view.stateAt(options.controlHead);
  if (atHead === undefined)
    throw new LfcpError("MISSING_DEPENDENCY", "the Control Head is not on the validated chain");
  if (options.profile.dataProfile !== atHead.dataProfile)
    throw new LfcpError(
      "DATA_PROFILE_MISMATCH",
      `the profile codec is for ${options.profile.dataProfile}, the Resource uses ${atHead.dataProfile}`,
    );
  const publisher = options.publisher.descriptor.principalId;
  if (!hasAbility(atHead, publisher, ABILITY.SNAPSHOT_PUBLISH))
    throw new LfcpError(
      "AUTHORIZATION_FAILED",
      "the publisher does not hold snapshot/publish at the Control Head (§29.2)",
    );
  const epoch = atHead.epoch.epoch;
  if (!bytesEqual(dekCommitment(atHead.resourceId, epoch, options.dek), atHead.epoch.dekCommitment))
    throw new LfcpError(
      "DEK_COMMITMENT_MISMATCH",
      `the DEK is not the one committed for epoch ${epoch} at the Control Head`,
    );
  const frontier = normalizeLiveHaves(options.frontier);
  const beyond = beyondCutoff(options.view, epoch, frontier);
  if (beyond !== undefined) throw new LfcpError("INVALID_STRUCTURE", beyond);
  const plaintext = options.profile.encode(options.value);

  const seq = await options.sequences.reserveNext(atHead.resourceId, epoch, publisher);
  options.guard?.claim(atHead.resourceId, epoch, publisher, seq);
  const sealed = sealSnapshot(
    {
      resourceId: atHead.resourceId,
      dataEpoch: epoch,
      snapshotSeq: seq,
      controlHead: atHead.head,
      frontier,
    },
    plaintext,
    options.dek,
    options.publisher,
  );
  return Object.freeze({ bytes: sealed.bytes, snapshotId: sealed.snapshotId, seq, epoch });
}
