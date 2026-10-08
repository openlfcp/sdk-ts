import type { PrincipalId, ResourceId } from "@openlfcp/core";
import { deriveDomainActorId } from "../admission/actor.js";

/**
 * Identifiers and value domains of SHARED-SECTIONS-PROFILE-01 (Working
 * Draft 0.3): the profile identifier, the actor domain of its §2 binding,
 * and the enumerations of §4.
 */

/** The profile identifier, as a Resource's Genesis names it. */
export const SECTIONS_PROFILE_ID = "org.openlfcp.shared-sections.v1";

/** §2: the actor domain this profile gives the inherited SOP §8 binding. */
export const SECTIONS_ACTOR_DOMAIN = "OPENLFCP-SHARED-SECTIONS-ACTOR-v1";

/**
 * §2: the Automerge actor ID of `principal` editing the section `resource`:
 * SHA-256(ASCII("OPENLFCP-SHARED-SECTIONS-ACTOR-v1") || resource_id || principal_id),
 * from the raw 32-byte IDs. It differs from the Shared Objects actor of the
 * same pair, so a change of one profile never passes as the other's.
 */
export function deriveSectionActorId(resource: ResourceId, principal: PrincipalId): Uint8Array {
  return deriveDomainActorId(SECTIONS_ACTOR_DOMAIN, resource, principal);
}

/** §4.2: the kinds of a node. */
export const NODE_KINDS = Object.freeze(["task", "paragraph", "item", "raw"] as const);
export type NodeKind = (typeof NODE_KINDS)[number];

/** §4.2: the kinds that hold collaborative Text. */
export const TEXT_KINDS: ReadonlySet<NodeKind> = new Set(["paragraph", "item", "raw"]);

/** §4.2: the kinds that can parent content; paragraph and raw nodes cannot. */
export const PARENT_KINDS: ReadonlySet<NodeKind> = new Set(["task", "item"]);

/** §4.2: list_style, on task and item nodes only. */
export const LIST_STYLES = Object.freeze(["bullet", "ordered"] as const);
export type ListStyle = (typeof LIST_STYLES)[number];

/** §3: the root containers, each a map. */
export const ROOT_MAPS = Object.freeze([
  "section",
  "objects",
  "nodes",
  "placements",
  "extensions",
] as const);
