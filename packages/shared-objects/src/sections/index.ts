/**
 * SHARED-SECTIONS-PROFILE-01 (org.openlfcp.shared-sections.v1, Working
 * Draft 0.3): profile dispatch, the profile's values and actor binding,
 * schema validation of a section document (LFCP-02-011), and its writer
 * with the section and creation intents (LFCP-02-012 to 016), and the
 * admission of received changes (LFCP-02-017).
 * `@openlfcp/shared-objects/sections`. Its admission (SOP §§7–18) is the
 * shared `@openlfcp/shared-objects/admission` with SECTIONS_ACTOR_DOMAIN.
 */

export {
  ADMISSION_ORDER,
  type AdmissionDiagnostic,
  SectionAdmissionError,
} from "./admission.js";
export {
  type ProfileModel,
  profileModel,
  SUPPORTED_DATA_PROFILES,
  taskRefModel,
} from "./dispatch.js";
export { SectionDocument, type ValueType } from "./document.js";
export {
  AUTHORING_BUDGET,
  type SectionIntent,
  type SectionIntentCode,
  SectionIntentError,
  type SectionLocalChange,
  type SectionReceiveResult,
  type SectionRefusal,
  SectionReplica,
  type SectionReplicaOptions,
  type SectionSnapshot,
  type SectionSnapshotNode,
  type SectionUnit,
  type StagedSectionChange,
  type TextEdit,
} from "./replica.js";
export {
  SECTION_DIAGNOSTIC_ORDER,
  type SectionDiagnostic,
  type SectionProblem,
  type SectionValidation,
  validateSection,
} from "./schema.js";
export {
  deriveTree,
  type SectionTree,
  type StructuralFact,
  type TreeEntry,
} from "./tree.js";
export {
  deriveSectionActorId,
  LIST_STYLES,
  type ListStyle,
  NODE_KINDS,
  type NodeKind,
  PARENT_KINDS,
  ROOT_MAPS,
  SECTIONS_ACTOR_DOMAIN,
  SECTIONS_PROFILE_ID,
  TEXT_KINDS,
} from "./values.js";
