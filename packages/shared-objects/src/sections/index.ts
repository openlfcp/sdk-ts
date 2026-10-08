/**
 * SHARED-SECTIONS-PROFILE-01 (org.openlfcp.shared-sections.v1, Working
 * Draft 0.3): profile dispatch, the profile's values and actor binding, and
 * schema validation of a section document (LFCP-02-011).
 * `@openlfcp/shared-objects/sections`. Its admission (SOP §§7–18) is the
 * shared `@openlfcp/shared-objects/admission` with SECTIONS_ACTOR_DOMAIN.
 */
export {
  type ProfileModel,
  profileModel,
  SUPPORTED_DATA_PROFILES,
  taskRefModel,
} from "./dispatch.js";
export { SectionDocument, type ValueType } from "./document.js";
export {
  SECTION_DIAGNOSTIC_ORDER,
  type SectionDiagnostic,
  type SectionProblem,
  type SectionValidation,
  validateSection,
} from "./schema.js";
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
