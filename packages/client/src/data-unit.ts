import {
  type ActorSequence,
  bytesEqual,
  type DataEpoch,
  type DataUnitId,
  LfcpError,
} from "@openlfcp/core";
import { dekCommitment, type ResourceDEK } from "@openlfcp/crypto";
import type { ActorSequenceReservation, SequenceReuseGuard } from "@openlfcp/storage";
import {
  ABILITY,
  type ControlView,
  type DataProfileCodec,
  hasAbility,
  type Signer,
  sealDataUnit,
} from "@openlfcp/wire";

/**
 * Creating a Data Unit (LFCP-WIRE-01 §8, §12, §26). The application value
 * becomes plaintext through its Data Profile codec, then LFCP encrypts and
 * signs it; only the resulting opaque bytes are ever sent.
 */

export interface CreateDataUnitOptions<T> {
  /** The writer's validated view of the Resource's Control Chain. */
  readonly view: ControlView;
  /** The Control Head the unit is authorized at (usually the latest one). */
  readonly controlHead: Uint8Array;
  /** The actor: the writer's signing key and descriptor. */
  readonly actor: Signer;
  /** The DEK of the current Data Epoch at `controlHead`. */
  readonly dek: ResourceDEK;
  /**
   * The only source of actor sequences (§8): durable in production
   * (LFCP-034 to LFCP-036). A sequence is never passed in directly.
   */
  readonly sequences: ActorSequenceReservation;
  /** Optional second line of defence against a sequence used twice in this process. */
  readonly guard?: SequenceReuseGuard;
  /**
   * The actor's unit at the previous sequence (§26.2), or null for its
   * first unit. A non-null value with sequence 1, or null after 1, is
   * refused (the reserved sequence is then abandoned, never reused).
   */
  readonly previousUnitId: DataUnitId | null;
  readonly profile: DataProfileCodec<T>;
  readonly value: T;
}

export interface CreatedDataUnit {
  /** The exact signed bytes: opaque, the only form sent to servers and peers. */
  readonly bytes: Uint8Array;
  readonly unitId: DataUnitId;
  readonly seq: ActorSequence;
  readonly epoch: DataEpoch;
}

/**
 * Creates an encrypted, signed Data Unit. Before a sequence is reserved,
 * it checks that the head is on the chain, that the profile is the
 * Resource's, that the actor holds data/write at the head and that the DEK
 * is the one committed for the head's current epoch; then it reserves the
 * next sequence and seals the unit (sealDataUnit).
 */
export async function createDataUnit<T>(
  options: CreateDataUnitOptions<T>,
): Promise<CreatedDataUnit> {
  const atHead = options.view.stateAt(options.controlHead);
  if (atHead === undefined)
    throw new LfcpError("MISSING_DEPENDENCY", "the Control Head is not on the validated chain");
  if (options.profile.dataProfile !== atHead.dataProfile)
    throw new LfcpError(
      "DATA_PROFILE_MISMATCH",
      `the profile codec is for ${options.profile.dataProfile}, the Resource uses ${atHead.dataProfile}`,
    );
  const actor = options.actor.descriptor.principalId;
  if (!hasAbility(atHead, actor, ABILITY.DATA_WRITE))
    throw new LfcpError(
      "AUTHORIZATION_FAILED",
      "the actor does not hold data/write at the Control Head (§26.3)",
    );
  const epoch = atHead.epoch.epoch;
  if (!bytesEqual(dekCommitment(atHead.resourceId, epoch, options.dek), atHead.epoch.dekCommitment))
    throw new LfcpError(
      "DEK_COMMITMENT_MISMATCH",
      `the DEK is not the one committed for epoch ${epoch} at the Control Head`,
    );
  const plaintext = options.profile.encode(options.value);

  const seq = await options.sequences.reserveNext(atHead.resourceId, actor);
  options.guard?.claim(atHead.resourceId, actor, seq);
  if ((seq === 1n) !== (options.previousUnitId === null))
    throw new LfcpError(
      "INVALID_STRUCTURE",
      seq === 1n
        ? "the actor's first unit (sequence 1) must have a null previous unit (§26.2)"
        : `sequence ${seq} needs the actor's unit at sequence ${seq - 1n} as its previous unit (§26.2)`,
    );
  const sealed = sealDataUnit(
    {
      resourceId: atHead.resourceId,
      dataEpoch: epoch,
      actorSeq: seq,
      prevDataUnitId: options.previousUnitId,
      controlHead: atHead.head,
    },
    plaintext,
    options.dek,
    options.actor,
  );
  return Object.freeze({ bytes: sealed.bytes, unitId: sealed.unitId, seq, epoch });
}
