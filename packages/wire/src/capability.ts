import {
  bytesEqual,
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  type PrincipalId,
  toHex,
} from "@openlfcp/core";
import type { ControlState } from "./chain.js";
import {
  type ControlRecord,
  type OwnerTransferAcceptPayload,
  type OwnerTransferOfferPayload,
  parseOwnerTransferAccept,
  parseOwnerTransferOffer,
} from "./control.js";
import { objectId, verifySignedObject } from "./cose.js";
import type { Parsed } from "./objects.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * The LFCP capability engine (LFCP-WIRE-01 §17, §18, §20, §19, §25.2).
 *
 * Authority comes only from the validated Control Chain: a Principal ID
 * holds an ability at a Control Head H because of the owner rule or of
 * grants and claims committed through H. There is no server account,
 * user table or hosting identity anywhere in this module, and nothing
 * here takes one.
 *
 * Everything is a pure function of a ControlState (the state at some head
 * H). Evaluating at an older H means using the state at that H (see
 * `stateAt` on a linear chain result), so a later revocation never
 * changes an earlier answer.
 */

/** §17.1 standard ability codes. */
export const ABILITY = Object.freeze({
  DATA_READ: 1n,
  DATA_WRITE: 2n,
  SNAPSHOT_PUBLISH: 3n,
  CAPABILITY_GRANT: 4n,
  CAPABILITY_REVOKE: 5n,
  KEY_DISTRIBUTE: 6n,
  KEY_ROTATE: 7n,
  ROUTE_UPDATE: 8n,
  OWNER_TRANSFER_OFFER: 9n,
  RESOURCE_TOMBSTONE: 10n,
  INVITE_CLAIM: 11n,
});

/** §17.1 names of the standard codes. */
export const ABILITY_NAMES: ReadonlyMap<bigint, string> = new Map([
  [1n, "data/read"],
  [2n, "data/write"],
  [3n, "snapshot/publish"],
  [4n, "capability/grant"],
  [5n, "capability/revoke"],
  [6n, "key/distribute"],
  [7n, "key/rotate"],
  [8n, "route/update"],
  [9n, "owner/transfer-offer"],
  [10n, "resource/tombstone"],
  [11n, "invite/claim"],
]);

/**
 * PROVISIONAL (gap A1 / G-CP6): only standard codes confer anything. An
 * unknown code is kept in its record but is never held, so a grant of
 * unknown codes only is valid and useless.
 */
export const isStandardAbility = (ability: bigint): boolean => ABILITY_NAMES.has(ability);

/** A grant created by a CAPABILITY_GRANT record or by a successful claim (§17.2, §18.1). */
export interface Grant {
  /** The ID of the Control Record that created it (§17.2). */
  readonly id: ControlRecordId;
  readonly source: "grant" | "claim";
  readonly issuer: PrincipalId;
  readonly subject: PrincipalId;
  readonly abilities: readonly bigint[];
  readonly delegable: readonly bigint[];
  readonly parentGrantId: ControlRecordId | null;
  /** §17.2 claim_limit, for invitation grants; null when absent. */
  readonly claimLimit: bigint | null;
  /** Claims consumed so far, counted in linear chain order (§18.1). */
  readonly claimsUsed: bigint;
  /** The revoking record, or null while not revoked (§17.3). */
  readonly revokedBy: ControlRecordId | null;
}

/** The capability part of ControlState. */
export interface CapabilityState {
  /** Every grant created through this head, by grant ID hex, active or not. */
  readonly grants: ReadonlyMap<string, Grant>;
}

const key = (id: Uint8Array): string => toHex(id);

/**
 * Whether a grant is active at this state: not revoked and, for a
 * delegated grant, its parent active too. INFERRED RULE (gap CAP-REVOKE):
 * §17.3 does not say whether revoking a parent invalidates delegated
 * children; LFCP-021 treats a child as active only while its parent is
 * active at the same head (prompt item 9).
 */
export function isGrantActive(state: CapabilityState, grantId: Uint8Array): boolean {
  const seen = new Set<string>();
  let grant = state.grants.get(key(grantId));
  while (grant !== undefined) {
    if (grant.revokedBy !== null) return false;
    if (grant.parentGrantId === null) return true;
    if (seen.has(key(grant.id))) return false;
    seen.add(key(grant.id));
    grant = state.grants.get(key(grant.parentGrantId));
  }
  return false;
}

const isOwner = (state: ControlState, principal: Uint8Array): boolean =>
  bytesEqual(state.owner.principalId, principal);

/**
 * Whether `principal` holds `ability` at the head of `state`: the owner
 * holds every standard ability implicitly (§17.1, no self-grant); anyone
 * else holds it through an active grant whose abilities list it.
 */
export function hasAbility(state: ControlState, principal: PrincipalId, ability: bigint): boolean {
  if (!isStandardAbility(ability)) return false;
  if (isOwner(state, principal)) return true;
  for (const g of state.grants.values()) {
    if (
      bytesEqual(g.subject, principal) &&
      g.abilities.includes(ability) &&
      isGrantActive(state, g.id)
    )
      return true;
  }
  return false;
}

/** Every standard ability `principal` holds at the head of `state`, ascending. */
export function abilitiesOf(state: ControlState, principal: PrincipalId): readonly bigint[] {
  return [...ABILITY_NAMES.keys()].filter((a) => hasAbility(state, principal, a));
}

/**
 * An authorization decision; a refusal names the rule. `code` marks the
 * refusals callers must tell apart (INVITE_CLAIM_EXHAUSTED: §18.1 rule 3,
 * which LFCP-022 reports separately; still AUTHORIZATION_FAILED on the wire).
 */
export type Authorization =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: string; readonly code?: "INVITE_CLAIM_EXHAUSTED" };

const ALLOW: Authorization = Object.freeze({ allowed: true });
const deny = (reason: string): Authorization => Object.freeze({ allowed: false, reason });

const subset = (list: readonly bigint[], of: readonly bigint[]): boolean =>
  list.every((a) => of.includes(a));

/** Whether the grant `target` descends from a grant whose subject is `principal`. */
function descendsFrom(state: CapabilityState, target: Grant, principal: PrincipalId): boolean {
  const seen = new Set<string>();
  let parentId = target.parentGrantId;
  while (parentId !== null && !seen.has(key(parentId))) {
    seen.add(key(parentId));
    const parent = state.grants.get(key(parentId));
    if (parent === undefined) return false;
    if (bytesEqual(parent.subject, principal)) return true;
    parentId = parent.parentGrantId;
  }
  return false;
}

/**
 * Whether the issuer of `record` had the authority the record needs, at
 * the state before it (the chain's previous head). Genesis is authorized by
 * verifyGenesis. Records MVP 0.1 does not apply are not evaluated here.
 */
export function authorizeControlRecord(record: ControlRecord, state: ControlState): Authorization {
  if (!record.mvpSupported) return ALLOW;
  const issuer = record.payload.issuer;
  const body = record.body;
  switch (body.type) {
    case "GENESIS":
      return ALLOW;
    case "CAPABILITY_GRANT": {
      // §17.2: "A non-owner issuer MUST prove authority to grant every
      // requested ability. If parent grant id is present: the parent grant
      // MUST be active; the issuer MUST be the subject of the parent grant;
      // every granted ability MUST be included in the parent's delegable
      // abilities."
      if (body.parentGrantId !== undefined) {
        const parent = state.grants.get(key(body.parentGrantId));
        if (parent === undefined) return deny("the parent grant does not exist (§17.2)");
        if (!isGrantActive(state, parent.id)) return deny("the parent grant is not active (§17.2)");
        if (!bytesEqual(parent.subject, issuer))
          return deny("the issuer is not the subject of the parent grant (§17.2)");
        if (!subset(body.abilities, parent.delegable))
          return deny("a granted ability is not delegable under the parent grant (§17.2)");
        // INFERRED RULE (gap CAP-DELEGABLE): what a child may delegate on stays
        // within what the parent lets its subject delegate.
        if (!subset(body.delegable, parent.delegable))
          return deny("a delegable ability is not delegable under the parent grant (§17.2)");
      } else if (!isOwner(state, issuer)) {
        return deny("a non-owner grant must prove its authority through a parent grant (§17.2)");
      }
      // INFERRED RULE (gap CAP-GRANT): a non-owner issuer must also hold
      // capability/grant; §17.1 defines it and §17.2 does not say whether
      // the parent's delegable list alone suffices.
      if (!isOwner(state, issuer) && !hasAbility(state, issuer, ABILITY.CAPABILITY_GRANT))
        return deny("the issuer does not hold capability/grant (§17.1)");
      return ALLOW;
    }
    case "CAPABILITY_REVOKE": {
      const target = state.grants.get(key(body.grantId));
      if (target === undefined) return deny("the revoked grant does not exist (§17.3)");
      if (target.revokedBy !== null) return deny("the grant is already revoked (§17.3)");
      if (isOwner(state, issuer)) return ALLOW;
      // §17.3: the issuer MUST "possess capability/revoke authority that
      // covers the target grant". PROVISIONAL (gap CAP-COVERS): "covers" =
      // the issuer issued the target grant, or the target descends from a
      // grant whose subject is the issuer.
      if (!hasAbility(state, issuer, ABILITY.CAPABILITY_REVOKE))
        return deny("the issuer does not hold capability/revoke (§17.3)");
      if (bytesEqual(target.issuer, issuer) || descendsFrom(state, target, issuer)) return ALLOW;
      return deny("the issuer's capability/revoke authority does not cover the grant (§17.3)");
    }
    case "CAPABILITY_CLAIM": {
      // §18.1 validation rules 1-5 (rule 6, coordinator serialization, is LFCP-022).
      const invitation = state.grants.get(key(body.invitationGrantId));
      if (invitation === undefined) return deny("the invitation grant does not exist (§18.1)");
      if (!isGrantActive(state, invitation.id))
        return deny("the invitation grant is not active (§18.1 rule 1)");
      if (!invitation.abilities.includes(ABILITY.INVITE_CLAIM))
        return deny("the invitation grant does not grant invite/claim (§18.1 rule 2)");
      if (invitation.claimLimit === null || invitation.claimsUsed >= invitation.claimLimit)
        return Object.freeze({
          allowed: false,
          reason: "the invitation grant has no claims left (§18.1 rule 3)",
          code: "INVITE_CLAIM_EXHAUSTED",
        });
      if (!bytesEqual(invitation.subject, issuer))
        return deny("the claim issuer is not the Invitation Principal (§18.1 rule 5)");
      // Rule 4: a subset of the invitation's abilities, excluding invite/claim
      // unless the invitation explicitly delegates it. PROVISIONAL (gap A1):
      // unknown codes request nothing, so they are not checked.
      const transferable = invitation.abilities.filter(
        (a) => a !== ABILITY.INVITE_CLAIM || invitation.delegable.includes(ABILITY.INVITE_CLAIM),
      );
      if (!subset(body.abilities.filter(isStandardAbility), transferable))
        return deny("the claim requests abilities beyond the invitation grant (§18.1 rule 4)");
      return ALLOW;
    }
    case "KEY_EPOCH":
      // §19: "The issuer MUST possess key/rotate."
      return hasAbility(state, issuer, ABILITY.KEY_ROTATE)
        ? ALLOW
        : deny("the issuer does not hold key/rotate (§19)");
    case "OWNER_TRANSFER_COMMIT":
      return verifyOwnerTransfer(record, state).authorization;
    case "ROUTE_UPDATE":
      // §20: "The issuer MUST possess route/update"; "The route version MUST
      // increase monotonically" (Genesis counts as route version 0, inferred).
      if (!hasAbility(state, issuer, ABILITY.ROUTE_UPDATE))
        return deny("the issuer does not hold route/update (§20)");
      return body.routeVersion > state.routeVersion
        ? ALLOW
        : deny("the route version does not increase (§20)");
    default:
      return ALLOW;
  }
}

/** The capability transitions of an applied record (called by applyRecord). */
export function applyCapabilities(
  grants: ReadonlyMap<string, Grant>,
  record: ControlRecord,
): ReadonlyMap<string, Grant> {
  const body = record.body;
  const id = controlRecordId(record.signed.id);
  switch (body.type) {
    case "CAPABILITY_GRANT": {
      const next = new Map(grants);
      next.set(
        key(id),
        Object.freeze({
          id,
          source: "grant",
          issuer: record.payload.issuer,
          subject: body.subject.principalId,
          abilities: body.abilities,
          delegable: body.delegable,
          parentGrantId: body.parentGrantId ?? null,
          claimLimit: body.claimLimit ?? null,
          claimsUsed: 0n,
          revokedBy: null,
        }),
      );
      return next;
    }
    case "CAPABILITY_REVOKE": {
      const target = grants.get(key(body.grantId));
      if (target === undefined) return grants;
      const next = new Map(grants);
      next.set(key(target.id), Object.freeze({ ...target, revokedBy: id }));
      return next;
    }
    case "CAPABILITY_CLAIM": {
      // §18.1: "A successful claim creates a new capability grant to the
      // claimant [and] consumes one claim from the Invitation Grant."
      // INFERRED RULE (gap CAP-CLAIM): the new grant is identified by the
      // claim record, delegates nothing, and has no parent, so revoking the
      // spent invitation grant does not revoke the claimant.
      const invitation = grants.get(key(body.invitationGrantId));
      const next = new Map(grants);
      if (invitation !== undefined)
        next.set(
          key(invitation.id),
          Object.freeze({ ...invitation, claimsUsed: invitation.claimsUsed + 1n }),
        );
      next.set(
        key(id),
        Object.freeze({
          id,
          source: "claim",
          issuer: record.payload.issuer,
          subject: body.claimant.principalId,
          abilities: body.abilities,
          delegable: [],
          parentGrantId: null,
          claimLimit: null,
          claimsUsed: 0n,
          revokedBy: null,
        }),
      );
      return next;
    }
    default:
      return grants;
  }
}

/**
 * §25.2 Key Package authority at the package's referenced Control Head:
 * the sender must hold key/distribute, and the recipient must hold
 * data/read, "except for an Invitation Principal explicitly authorized by
 * an active invite grant" (an active grant to the recipient that includes
 * invite/claim). `epoch` is the package's Data Epoch; whether that epoch
 * is recognized at the head is checked with the epoch rules (LFCP-023,
 * LFCP-024).
 */
export function canDistributeKey(
  state: ControlState,
  sender: PrincipalId,
  recipient: PrincipalId,
  _epoch: DataEpoch,
): Authorization {
  if (!hasAbility(state, sender, ABILITY.KEY_DISTRIBUTE))
    return deny("the sender does not hold key/distribute (§25.2)");
  if (hasAbility(state, recipient, ABILITY.DATA_READ)) return ALLOW;
  for (const g of state.grants.values()) {
    if (
      bytesEqual(g.subject, recipient) &&
      g.abilities.includes(ABILITY.INVITE_CLAIM) &&
      isGrantActive(state, g.id)
    )
      return ALLOW;
  }
  return deny("the recipient holds neither data/read nor an active invite grant (§25.2)");
}

/** A verified ownership transfer: the new owner's descriptor, from the offer. */
export interface VerifiedOwnerTransfer {
  readonly authorization: Authorization;
  readonly newOwner?: PrincipalDescriptor;
}

/**
 * The §23.3 verifier for an OWNER_TRANSFER_COMMIT, at the state before it.
 * Verification only: there is no transfer UI or flow (deferred from MVP 0.1).
 *
 * §23.3 "A verifier MUST confirm":
 *  1. the offer is signed by the current owner;
 *  2. the offer references the current Control Head;
 *  3. the offer names the accepting Principal;
 *  4. the acceptance is signed by that Principal;
 *  5. the commit itself is signed by that Principal (here: issued by it;
 *     the chain verifies the signature against the issuer);
 *  6. the expected next Control Sequence matches the commit sequence.
 * Also, from §23.1 and §23.2: the offer and accept are canonical signed
 * objects of this Resource, and the accept names the exact offer ID (the
 * §10.6 object ID of the offer bytes). Any failure is a refusal
 * (AUTHORIZATION_FAILED); §23 names no code.
 */
export function verifyOwnerTransfer(
  record: ControlRecord,
  state: ControlState,
): VerifiedOwnerTransfer {
  const body = record.body;
  if (body.type !== "OWNER_TRANSFER_COMMIT")
    return { authorization: deny("not an ownership transfer commit") };
  let offer: Parsed<OwnerTransferOfferPayload>;
  let accept: Parsed<OwnerTransferAcceptPayload>;
  try {
    offer = parseOwnerTransferOffer(body.offer);
    accept = parseOwnerTransferAccept(body.accept);
  } catch {
    return {
      authorization: deny("the offer or accept is not a valid signed object (§23.1, §23.2)"),
    };
  }
  const o = offer.payload;
  const a = accept.payload;
  if (!bytesEqual(o.resourceId, state.resourceId) || !bytesEqual(a.resourceId, state.resourceId))
    return { authorization: deny("the offer or accept is for another Resource (§23.1, §23.2)") };
  const offerSigned = verifySignedObject(offer.signed, state.owner);
  if (!offerSigned.valid)
    return {
      authorization: deny(
        `the offer is not signed by the current owner (${offerSigned.reason}, §23.3 rule 1)`,
      ),
    };
  if (!bytesEqual(o.controlHead, state.head))
    return {
      authorization: deny("the offer does not reference the current Control Head (§23.3 rule 2)"),
    };
  if (!bytesEqual(a.newOwner, o.proposedOwner.principalId))
    return {
      authorization: deny("the accept is not by the Principal the offer names (§23.3 rule 3)"),
    };
  if (!bytesEqual(a.offerId, objectId(offer.signed.bytes)))
    return { authorization: deny("the accept does not name this offer (§23.2)") };
  const acceptSigned = verifySignedObject(accept.signed, o.proposedOwner);
  if (!acceptSigned.valid)
    return {
      authorization: deny(
        `the accept is not signed by the new owner (${acceptSigned.reason}, §23.3 rule 4)`,
      ),
    };
  if (!bytesEqual(record.payload.issuer, o.proposedOwner.principalId))
    return { authorization: deny("the commit is not issued by the new owner (§23.3 rule 5)") };
  if (o.expectedControlSeq !== record.payload.controlSeq)
    return {
      authorization: deny(
        "the offer's expected Control Sequence is not the commit's (§23.3 rule 6)",
      ),
    };
  return { authorization: ALLOW, newOwner: o.proposedOwner };
}

/**
 * The descriptor a transfer commit carries for its own issuer: the offer's
 * proposed owner (self-certifying, §7), so a new owner never granted
 * before can still be verified. Undefined for other records.
 */
export function transferIssuerDescriptor(record: ControlRecord): PrincipalDescriptor | undefined {
  if (record.body.type !== "OWNER_TRANSFER_COMMIT") return undefined;
  try {
    const proposed = parseOwnerTransferOffer(record.body.offer).payload.proposedOwner;
    return bytesEqual(proposed.principalId, record.payload.issuer) ? proposed : undefined;
  } catch {
    return undefined;
  }
}
