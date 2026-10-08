/** Name of this package. */
export const PACKAGE = "@openlfcp/storage";

export {
  LOCAL_STATE_SCHEME,
  type LocalStateCipher,
  type LocalStateEvent,
  LocalStateKeyring,
  type LocalStateMeta,
  localStateAad,
  localStateKeyRef,
  type OpenedLocal,
  type ResealRow,
  reseal,
} from "./local-state.js";
export { InMemoryLfcpStorage } from "./memory.js";
export {
  dekSecretRef,
  InMemorySecretStore,
  isSecretRef,
  principalKeySecretRef,
  type SecretKind,
  type SecretRef,
  type SecretStore,
  secretRef,
} from "./secrets.js";
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
export type {
  CommitResult,
  ControlConflictRow,
  ControlHeadRow,
  ControlReader,
  ControlRecordRow,
  DataUnitReader,
  DataUnitRow,
  DataUnitStatus,
  EpochRow,
  KeyPackageReader,
  KeyPackageRow,
  LfcpStorage,
  LocalMarkReader,
  OutboundBlock,
  OutboundItem,
  OutboundKind,
  OutboundReader,
  ProfileCheckpoint,
  ProfileStateReader,
  ResourceReader,
  ResourceRow,
  RouteRow,
  SeenRecord,
  SnapshotReader,
  SnapshotRow,
  StorageWrite,
  StoredDataUnit,
  SyncStateReader,
  SyncStateRow,
} from "./store.js";
