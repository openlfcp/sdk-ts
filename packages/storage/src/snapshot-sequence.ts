import {
  type DataEpoch,
  dataEpoch,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
  UINT64_MAX,
} from "@openlfcp/core";

/**
 * Snapshot Sequence allocation (LFCP-WIRE-01 §29, §29.1.2). A Snapshot's
 * nonce is 0x00000000 || uint64_be(snapshot_sequence) under a key that
 * depends on (Resource, Data Epoch, publisher), so a sequence used twice
 * for one (resource, data_epoch, publisher) can reuse a nonce. Sequences
 * start at 1 and never go back.
 */
export interface SnapshotSequenceReservation {
  /**
   * Reserves the next Snapshot Sequence for `publisher` in `epoch` of
   * `resource`. Same contract as ActorSequenceReservation: durable before
   * the promise resolves, never the same value twice for one tuple, across
   * restarts and concurrent callers; an unused reservation is abandoned,
   * never returned. OUT_OF_RANGE once 2^64 - 1 was handed out. Durable
   * implementations belong to LFCP-034 and LFCP-035.
   */
  reserveNext(resource: ResourceId, epoch: DataEpoch, publisher: PrincipalId): Promise<bigint>;
}

const tupleKey = (resource: ResourceId, epoch: DataEpoch, publisher: PrincipalId): string =>
  `${toHex(resource)}:${dataEpoch(epoch)}:${toHex(publisher)}`;

/**
 * FOR TESTS AND DEVELOPMENT ONLY. NOT CRASH-SAFE: a restart starts again at
 * 1 and reuses nonces. Production publishers need a durable
 * SnapshotSequenceReservation (LFCP-034, LFCP-035).
 */
export class InMemorySnapshotSequenceReservation implements SnapshotSequenceReservation {
  readonly #last = new Map<string, bigint>();

  reserveNext(resource: ResourceId, epoch: DataEpoch, publisher: PrincipalId): Promise<bigint> {
    const key = tupleKey(resource, epoch, publisher);
    const last = this.#last.get(key) ?? 0n;
    if (last >= UINT64_MAX)
      return Promise.reject(
        new LfcpError("OUT_OF_RANGE", "the Snapshot Sequence space is exhausted (§29)"),
      );
    this.#last.set(key, last + 1n);
    return Promise.resolve(last + 1n);
  }
}

/**
 * A local check that no (resource, data_epoch, publisher, sequence) is used
 * twice, as a second line of defence where Snapshots are created. In memory
 * only; it does not replace a durable reservation.
 */
export class SnapshotSequenceGuard {
  readonly #seen = new Set<string>();

  /** Records the tuple, or throws SEQUENCE_REUSE when it was recorded before. */
  claim(resource: ResourceId, epoch: DataEpoch, publisher: PrincipalId, seq: bigint): void {
    const key = `${tupleKey(resource, epoch, publisher)}:${seq}`;
    if (this.#seen.has(key))
      throw new LfcpError(
        "SEQUENCE_REUSE",
        `Snapshot Sequence ${seq} was already used for this (Resource, epoch, publisher) (§29)`,
      );
    this.#seen.add(key);
  }
}
