/** Name of this package. */
export const PACKAGE = "@openlfcp/client";

export {
  type ApplyOutcome,
  type DataProfileHandler,
  DataUnitApplier,
  type DataUnitApplierOptions,
  type EpochReconciliation,
  type EquivocationOutcome,
  type ExcludedUnit,
  type ProfileApplyResult,
  type ProfileDiagnostic,
  type ProfileExcludeResult,
  type ProfileUnit,
} from "./apply.js";
export { type CheckpointSource, ProfileCheckpointer } from "./checkpoint.js";
export {
  type ConnectionEvents,
  type ConnectionOptions,
  LFCP_SUBPROTOCOL,
  LfcpConnection,
  platformWebSocket,
  type WebSocketFactory,
  type WebSocketLike,
} from "./connection.js";
export { type CreateDataUnitOptions, type CreatedDataUnit, createDataUnit } from "./data-unit.js";
export {
  EngineGuard,
  type EngineItem,
  isEngineTrap,
  type Suspicion,
  snapshotItem,
  unitItem,
} from "./engine-guard.js";
export {
  type AcceptedInvitation,
  type AcceptInvitationOptions,
  type AcceptInvitationProgress,
  type AcceptInvitationStage,
  acceptInvitation,
  type CreatedInvitation,
  type CreateInvitationOptions,
  createInvitation,
  DEFAULT_INVITATION_ABILITIES,
  InvitationLink,
} from "./invite.js";
export {
  type AckOutcome,
  type BlockedItem,
  exponentialBackoff,
  type NackOutcome,
  type OutboundMessage,
  OutboundQueue,
  type OutboundQueueOptions,
  type ResourceSyncState,
  type RetryPolicy,
  type RetryReason,
  resourceSyncState,
  type StaleOutboundUnit,
  snapshotFrontier,
} from "./outbound.js";
export {
  createQueuedSnapshot,
  outboundItem,
  queueControlRecord,
  queueKeyEpoch,
  queueKeyPackage,
  queueSnapshot,
} from "./queue.js";
export {
  intentsHash,
  OperationIdReusedError,
  type Receipt,
  receiptOf,
  releaseReceipt,
} from "./receipts.js";
export {
  type ResourcePhase,
  type ResourcePhaseEvent,
  resourcePhaseTransition,
} from "./resource-state.js";
export { type CreatedSnapshot, type CreateSnapshotOptions, createSnapshot } from "./snapshot.js";
export {
  adoptStoredDeks,
  type CommitOperationOptions,
  commitOperation,
  createQueuedDataUnit,
  dataUnitRow,
  dekResolver,
  latestAcceptedOwnUnit,
  loadControlChain,
  StoredSeenUnits,
  saveControlChain,
  saveControlConflict,
} from "./storage.js";
export {
  defaultReconnect,
  type ReconnectPolicy,
  type ResourceBinding,
  type ResourceRefusal,
  type SnapshotBinding,
  SyncClient,
  type SyncClientOptions,
  type SyncEvent,
  startSyncDriver,
  TERMINAL_RESOURCE_CODES,
} from "./sync-client.js";
