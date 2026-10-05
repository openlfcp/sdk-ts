/**
 * SHARED-OBJECTS-PROFILE-01 (org.openlfcp.shared-objects.v1): the Shared
 * Task model and profile validation over logical state (LFCP-030), and its
 * Automerge binding (LFCP-031).
 */
export const PACKAGE = "@openlfcp/shared-objects";

export {
  type CheckedChange,
  checkChange,
  checkSaveHeader,
  frameChange,
  frameSnapshot,
  unframeChange,
  unframeSnapshot,
} from "./automerge-bytes.js";
export {
  type BuiltReplica,
  type LocalChange,
  type ObjectChange,
  ObjectIdCollisionError,
  type ObjectStatus,
  type ReceiveResult,
  type ReplicaIntent,
  type ReplicaOptions,
  type ReplicaValidation,
  type ResolveFieldConflict,
  resolveFieldConflict,
  SCALAR_FIELDS,
  type ScalarField,
  type ScalarView,
  SharedObjectsReplica,
  type TaskView,
} from "./replica.js";
export {
  addTag,
  assign,
  cancel,
  clearDue,
  clearScheduled,
  complete,
  createTask,
  deleteTask,
  type NewTask,
  type ParsedTask,
  ProfileError,
  parseTask,
  removeTag,
  reopen,
  restoreTask,
  setDue,
  setPriority,
  setScheduled,
  setStatus,
  setTitle,
  type Task,
  type TaskChange,
  type TaskIntent,
  type TaskPriority,
  type TaskStatus,
  taskToJson,
  unassign,
} from "./task.js";
export {
  isMap,
  type Json,
  objectProblems,
  type ProfileDiagnostic,
  type ProfileProblem,
  pointerToken,
  type RootValidation,
  validateRoot,
  validateTransition,
} from "./validate.js";
export {
  deriveActorId,
  FRAMING_VERSION,
  frameProfilePayload,
  isLocalDate,
  isNamespacedValue,
  isPrincipalRef,
  isReverseDomain,
  isUtcTimestamp,
  PROFILE_ID,
  type PrincipalRef,
  parsePrincipalRef,
  principalRef,
  unframeProfilePayload,
} from "./values.js";
