/** Name of this package. */
export const PACKAGE = "@openlfcp/storage";

export {
  type ActorSequenceReservation,
  InMemoryActorSequenceReservation,
  nextActorSequence,
  SequenceReuseGuard,
} from "./sequence.js";
export {
  InMemorySnapshotSequenceReservation,
  SnapshotSequenceGuard,
  type SnapshotSequenceReservation,
} from "./snapshot-sequence.js";
