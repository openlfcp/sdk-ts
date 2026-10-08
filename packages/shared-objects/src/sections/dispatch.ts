import { PROFILE_ID } from "../values.js";
import { SECTIONS_PROFILE_ID } from "./values.js";

/**
 * Profile dispatch (SHARED-SECTIONS-PROFILE-01 §1, §17): a Resource's
 * Genesis names its Data Profile, and that profile alone selects the model
 * that reads and writes it. A Resource created as Shared Objects stays one;
 * nothing is inferred from the document's contents, and a Task reference
 * (`#task:`) is read with the model of the Resource it names, not by its
 * textual shape.
 */

/** The models this package implements, by Data Profile. */
export const SUPPORTED_DATA_PROFILES = Object.freeze([PROFILE_ID, SECTIONS_PROFILE_ID] as const);

export type ProfileModel =
  | { readonly kind: "shared-objects"; readonly dataProfile: typeof PROFILE_ID }
  | { readonly kind: "shared-sections"; readonly dataProfile: typeof SECTIONS_PROFILE_ID }
  /**
   * LFCP-WIRE-01 §62: no model here reads this profile. The Resource is
   * neither interpreted nor written; nothing is created or changed.
   */
  | {
      readonly kind: "profile-unsupported";
      readonly code: "PROFILE_UNSUPPORTED";
      readonly dataProfile: string;
    };

/**
 * The model of a Resource whose validated Genesis (its Control Chain state)
 * names `dataProfile`. Exact match only: no prefix, version or case folding.
 */
export function profileModel(dataProfile: string): ProfileModel {
  if (dataProfile === PROFILE_ID) return Object.freeze({ kind: "shared-objects", dataProfile });
  if (dataProfile === SECTIONS_PROFILE_ID)
    return Object.freeze({ kind: "shared-sections", dataProfile });
  return Object.freeze({ kind: "profile-unsupported", code: "PROFILE_UNSUPPORTED", dataProfile });
}

/**
 * §17: the model that reads a Task reference into a Resource, chosen by that
 * Resource's Data Profile. A standalone Task in a section Resource is a
 * section Task; the same reference shape in a Shared Objects Resource is a
 * Shared Objects Task.
 */
export function taskRefModel(resourceDataProfile: string): ProfileModel {
  return profileModel(resourceDataProfile);
}
