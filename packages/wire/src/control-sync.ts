import { bytesEqual } from "@openlfcp/core";
import type { ControlHeadRef } from "./message.js";

/**
 * Control Plane anti-entropy planning (LFCP-WIRE-01 §44, §45, §67): from
 * our Control Head and the heads a peer announces in CONTROL_HAVE (or
 * RESOURCE_OPENED), decide what to request. Pure; no network loop.
 *
 * A fork is surfaced, never resolved: two or more peer heads (§42, §44),
 * or a peer head at a sequence we hold whose record ID is not ours (§13.2).
 * The plan then asks for the contested records, so the receiver can
 * validate them (validateControlChain reports CONTROL_CONFLICT) instead of
 * choosing a branch.
 */

/** What we know of our chain: its head, and the record ID at any sequence we hold. */
export interface LocalControl {
  readonly head: ControlHeadRef;
  readonly recordIdAt: (seq: bigint) => Uint8Array | undefined;
}

export type ControlSyncPlan =
  /** Both sides have the same head. */
  | { readonly kind: "in-sync" }
  /** G-HV2: an empty CONTROL_HAVE means the peer has no Control Records. */
  | { readonly kind: "peer-empty" }
  /** The peer is ahead on our chain: CONTROL_GET(start..end) (§45, §67). */
  | { readonly kind: "fetch"; readonly start: bigint; readonly end: bigint }
  /** The peer is behind on our chain; it may fetch from us. Nothing to request. */
  | { readonly kind: "peer-behind"; readonly peerSeq: bigint }
  /**
   * A fork: never resolved here. `fetch` covers the contested sequences
   * (and anything the peer has beyond them), so every competing record can
   * be validated.
   */
  | {
      readonly kind: "fork";
      readonly reason: "PEER_HEADS" | "DIVERGED";
      readonly heads: readonly ControlHeadRef[];
      readonly fetch: { readonly start: bigint; readonly end: bigint };
    };

/** Plans Control synchronization against a peer's announced heads. `local` is null when we hold no records. */
export function planControlSync(
  local: LocalControl | null,
  peerHeads: readonly ControlHeadRef[],
): ControlSyncPlan {
  if (peerHeads.length === 0) return Object.freeze({ kind: "peer-empty" });
  const maxSeq = peerHeads.reduce((m, h) => (h.seq > m ? h.seq : m), 0n);
  if (peerHeads.length > 1) {
    const minSeq = peerHeads.reduce((m, h) => (h.seq < m ? h.seq : m), maxSeq);
    const ours = local?.head.seq;
    const start = ours === undefined ? 0n : ours < minSeq ? ours + 1n : minSeq;
    return Object.freeze({
      kind: "fork",
      reason: "PEER_HEADS",
      heads: Object.freeze([...peerHeads]),
      fetch: Object.freeze({ start, end: maxSeq }),
    });
  }
  const peer = peerHeads[0] as ControlHeadRef;
  if (local === null) return Object.freeze({ kind: "fetch", start: 0n, end: peer.seq });
  if (peer.seq <= local.head.seq) {
    const ours = local.recordIdAt(peer.seq);
    if (ours === undefined || !bytesEqual(ours, peer.recordId))
      return Object.freeze({
        kind: "fork",
        reason: "DIVERGED",
        heads: Object.freeze([peer]),
        fetch: Object.freeze({ start: peer.seq, end: peer.seq }),
      });
    return peer.seq === local.head.seq
      ? Object.freeze({ kind: "in-sync" })
      : Object.freeze({ kind: "peer-behind", peerSeq: peer.seq });
  }
  return Object.freeze({ kind: "fetch", start: local.head.seq + 1n, end: peer.seq });
}

/** The LocalControl of a validated linear chain (records[i] is at sequence i from Genesis). */
export function localControlOf(chain: {
  readonly state: { readonly head: Uint8Array; readonly seq: bigint };
  readonly records: readonly {
    readonly signed: { readonly id: Uint8Array };
    readonly payload: { readonly controlSeq: bigint };
  }[];
}): LocalControl {
  const byseq = new Map(chain.records.map((r) => [r.payload.controlSeq, r.signed.id]));
  return Object.freeze({
    head: Object.freeze({ seq: chain.state.seq, recordId: chain.state.head as never }),
    recordIdAt: (seq: bigint) => byseq.get(seq),
  });
}
