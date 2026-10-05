import {
  type ActorSequence,
  actorSequence,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
  UINT64_MAX,
} from "@openlfcp/core";

/**
 * Actor sequence allocation (LFCP-WIRE-01 §8, §12).
 *
 * A writer's Data Unit nonce is 0x00000000 || uint64_be(seq) under a key
 * that depends on (Resource, Data Epoch, Principal). A sequence used twice
 * for one (Resource, Principal) can reuse a nonce under the same key, so
 * sequences are scoped to (Resource, Principal), start at 1, and never go
 * back, not even when the Data Epoch changes.
 */
export interface ActorSequenceReservation {
  /**
   * Reserves the next actor sequence for `principal` writing to `resource`.
   *
   * Contract: the reservation is durable before the promise resolves (a
   * crash after it resolves can never hand out the same value again), and
   * the same (resource, principal, seq) is never returned twice, across
   * Data Epochs, restarts and concurrent callers. A caller that cannot use
   * a reserved sequence abandons it; it is never returned to the pool.
   *
   * When the state is lost and cannot be reconstructed safely, the writer
   * must switch to a new Principal for that Resource (§8). When the space
   * is exhausted (2^64 - 1 was handed out) it rejects with OUT_OF_RANGE.
   *
   * The durable implementations belong to the storage tasks: LFCP-034
   * (storage abstraction), LFCP-035 (Node persistence adapter, "atomic
   * enough to prevent sequence reuse") and LFCP-036 (pending outbound
   * queue: a retry never regenerates a Data Unit with the same sequence).
   */
  reserveNext(resource: ResourceId, principal: PrincipalId): Promise<ActorSequence>;
}

/** The sequence after `last` (1 when nothing was reserved yet); OUT_OF_RANGE after 2^64 - 1. */
export function nextActorSequence(last: ActorSequence | undefined): ActorSequence {
  if (last === undefined) return actorSequence(1n);
  if (last >= UINT64_MAX)
    throw new LfcpError(
      "OUT_OF_RANGE",
      "the actor sequence space is exhausted; use a new Principal for this Resource (§8)",
    );
  return actorSequence(last + 1n);
}

const tupleKey = (resource: ResourceId, principal: PrincipalId): string =>
  `${toHex(resource)}:${toHex(principal)}`;

/**
 * FOR TESTS AND DEVELOPMENT ONLY. NOT CRASH-SAFE: the state lives in
 * memory, so a restart starts again at 1 and reuses nonces. Production
 * writers need a durable ActorSequenceReservation (LFCP-034, LFCP-035).
 */
export class InMemoryActorSequenceReservation implements ActorSequenceReservation {
  readonly #last = new Map<string, ActorSequence>();

  reserveNext(resource: ResourceId, principal: PrincipalId): Promise<ActorSequence> {
    try {
      const key = tupleKey(resource, principal);
      const next = nextActorSequence(this.#last.get(key));
      this.#last.set(key, next);
      return Promise.resolve(next);
    } catch (e) {
      return Promise.reject(e);
    }
  }
}

/**
 * A local check that no (resource, principal, seq) is used twice, as a
 * second line of defence where Data Units are created. It remembers what
 * it has seen in memory only; it does not replace a durable reservation.
 */
export class SequenceReuseGuard {
  readonly #seen = new Map<string, Set<bigint>>();

  /** Records the tuple, or throws SEQUENCE_REUSE when it was recorded before. */
  claim(resource: ResourceId, principal: PrincipalId, seq: ActorSequence): void {
    const s = actorSequence(seq);
    const key = tupleKey(resource, principal);
    let used = this.#seen.get(key);
    if (used === undefined) {
      used = new Set();
      this.#seen.set(key, used);
    }
    if (used.has(s))
      throw new LfcpError(
        "SEQUENCE_REUSE",
        `actor sequence ${s} was already used for this (Resource, Principal) (§8)`,
      );
    used.add(s);
  }

  /** True when the tuple was claimed before. */
  has(resource: ResourceId, principal: PrincipalId, seq: ActorSequence): boolean {
    return this.#seen.get(tupleKey(resource, principal))?.has(seq) ?? false;
  }
}
