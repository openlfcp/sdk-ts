import { ID32_LENGTH, LfcpError, type PrincipalId, type ResourceId } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { ProfileInvalidError } from "../profile-invalid.js";
import type { CheckedChange } from "./framing.js";

/**
 * SHARED-OBJECTS-PROFILE-01 §8, the actor binding, for any profile that
 * inherits it with its own domain (SHARED-SECTIONS-PROFILE-01 §2):
 * SHA-256(ASCII(domain) || resource_id || principal_id), from the raw
 * 32-byte IDs.
 */
export function deriveDomainActorId(
  domain: string,
  resource: ResourceId,
  principal: PrincipalId,
): Uint8Array {
  for (const [what, id] of [
    ["the Resource ID", resource],
    ["the Principal ID", principal],
  ] as const) {
    if (!(id instanceof Uint8Array) || id.length !== ID32_LENGTH)
      throw new LfcpError("INVALID_LENGTH", `${what} must be the raw 32-byte ID`);
  }
  const prefix = Uint8Array.from(domain, (c) => c.charCodeAt(0));
  const input = new Uint8Array(prefix.length + 2 * ID32_LENGTH);
  input.set(prefix, 0);
  input.set(resource, prefix.length);
  input.set(principal, prefix.length + ID32_LENGTH);
  return sha256(input);
}

/**
 * §8, §11: a Data Unit carries only changes of its signer's actor. Throws
 * PROFILE_INVALID / CHANGE_ACTOR_MISMATCH otherwise; `actor` is the hex
 * actor ID the signer's binding gives.
 */
export function checkChangeActor(change: CheckedChange, actor: string): CheckedChange {
  if (change.actor !== actor)
    throw new ProfileInvalidError(
      "CHANGE_ACTOR_MISMATCH",
      `the change's Automerge actor ${change.actor} is not the §8 actor ${actor} of the unit's signer (§11, SO-SEC1)`,
    );
  return change;
}
