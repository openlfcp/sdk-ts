/**
 * The admission of SHARED-OBJECTS-PROFILE-01 §§7–18 that every profile
 * inheriting them shares (SHARED-SECTIONS-PROFILE-01 §2; LFCP-02-085),
 * checked before the Automerge engine sees a change or a Snapshot:
 *
 * - framing (§11, §13): [1, change] and [1, full save], one uncompressed
 *   change chunk with a verified checksum;
 * - limits (§11.1, §11.2, §13.1): the exact change expansion limits, the
 *   document depth bound, the Snapshot limits with their floor;
 * - the canonical change encoding (§11.3), by the format's properties;
 * - actor binding (§8), with the profile's domain;
 * - sequence admission (§14.1): duplicates, dependencies, the sequence
 *   check, and holding a change whose actor and sequence another change
 *   has (POST-001).
 *
 * It knows no profile semantics: a profile's own rules (its values, §74.1)
 * run after it, on admitted changes only. `@openlfcp/shared-objects/admission`.
 */
export { checkChangeActor, deriveDomainActorId } from "./actor.js";
export { checkCanonicalChange, type ParsedChange, type ParsedOp } from "./canonical.js";
export {
  type CheckedChange,
  checkChange,
  checkSaveHeader,
  FRAMING_VERSION,
  frameChange,
  frameProfilePayload,
  frameSnapshot,
  parsedOf,
  unframeChange,
  unframeProfilePayload,
  unframeSnapshot,
} from "./framing.js";
export {
  CHANGE_LIMITS,
  type ChunkExpansion,
  checkChangeExpansion,
  checkSnapshotExpansion,
  MAX_DOCUMENT_DEPTH,
  SNAPSHOT_LIMITS_FLOOR,
  type SnapshotLimits,
} from "./limits.js";
export {
  admitBatch,
  admitChange,
  type BatchAdmission,
  type ChangeAdmission,
  type DocumentSequences,
  type RefusedChange,
} from "./sequence.js";
