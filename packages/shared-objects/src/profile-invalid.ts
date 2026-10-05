import { LfcpError } from "@openlfcp/core";
import type { ProfileDiagnostic } from "./validate.js";

/**
 * PROFILE_INVALID thrown for a rejected profile plaintext or value, with
 * its §74.1 diagnostic: CHANGE_ACTOR_MISMATCH (§8, §11) or
 * INVALID_AUTOMERGE_BYTES (§11, §13).
 */
export class ProfileInvalidError extends LfcpError {
  readonly diagnostic: ProfileDiagnostic;

  constructor(diagnostic: ProfileDiagnostic, message: string) {
    super("PROFILE_INVALID", message);
    this.name = "ProfileInvalidError";
    this.diagnostic = diagnostic;
  }
}
