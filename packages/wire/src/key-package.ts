import {
  bytesEqual,
  type DataEpoch,
  dataEpoch,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { canDistributeKey } from "./capability.js";
import { encode } from "./cbor/index.js";
import { verifySignedObject } from "./cose.js";
import type { ControlView } from "./epoch.js";
import { expectedSignerOf, type KeyPackagePayload, type Parsed } from "./objects.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * Key Packages (LFCP-WIRE-01 §25): HPKE delivery of a Resource DEK to one
 * recipient Principal, signed by its sender.
 *
 * This module holds the parts that need no HPKE: the exact §25.1 info and
 * AAD, and the §25.2 checks a receiver runs against the Control Chain
 * before opening a package. Opening failures (the package does not open
 * for its recipient, or its DEK does not match the commitment) are
 * client-local: the package is ignored and surfaced; there is no wire code
 * (ADR 0001 N5).
 */

const KEY_LABEL = "LFCP-KEY-v1";

/** §25.1: HPKE info = deterministic CBOR of ["LFCP-KEY-v1", resource_id, data_epoch, recipient]. */
export function keyPackageHpkeInfo(
  resource: ResourceId,
  epoch: DataEpoch,
  recipient: PrincipalId,
): Uint8Array {
  return encode([KEY_LABEL, resource, dataEpoch(epoch), recipient]);
}

/** §25.1: HPKE AAD = deterministic CBOR of [resource_id, data_epoch, control_head]. */
export function keyPackageHpkeAad(
  resource: ResourceId,
  epoch: DataEpoch,
  controlHead: Uint8Array,
): Uint8Array {
  return encode([resource, dataEpoch(epoch), controlHead]);
}

export type KeyPackageCheck =
  | { readonly kind: "authorized"; readonly sender: PrincipalDescriptor }
  | {
      readonly kind: "rejected";
      readonly reason:
        | "OTHER_RESOURCE"
        | "UNKNOWN_CONTROL_HEAD"
        | "UNKNOWN_EPOCH"
        | "UNKNOWN_SENDER"
        | "SIGNATURE"
        | "UNAUTHORIZED";
      readonly wireCode: string;
      readonly message: string;
    };

const reject = (
  reason: Extract<KeyPackageCheck, { kind: "rejected" }>["reason"],
  wireCode: string,
  message: string,
): KeyPackageCheck => Object.freeze({ kind: "rejected", reason, wireCode, message });

/**
 * The §25.2 checks of a received Key Package against the validated chain,
 * all at the package's referenced Control Head:
 *
 * - the head is on the chain and the package's epoch is known there.
 *   Packages of closed epochs stay valid (PROVISIONAL G-EP6): they are
 *   needed to read history. Otherwise MISSING_DEPENDENCY (G-EP2);
 * - the package is signed by its sender (kid = sender): INVALID_SIGNATURE;
 * - the sender held key/distribute and the recipient data/read, or an
 *   active invite grant (canDistributeKey, LFCP-021): AUTHORIZATION_FAILED.
 *
 * Opening the package and checking the DEK commitment come after this.
 */
export function verifyKeyPackage(
  view: ControlView,
  parsed: Parsed<KeyPackagePayload>,
): KeyPackageCheck {
  const p = parsed.payload;
  if (!bytesEqual(p.resourceId, view.state.resourceId))
    return reject("OTHER_RESOURCE", "MALFORMED_MESSAGE", "the package is for another Resource");
  const atHead = view.stateAt(p.controlHead);
  if (atHead === undefined)
    return reject(
      "UNKNOWN_CONTROL_HEAD",
      "MISSING_DEPENDENCY",
      `Control Head ${toHex(p.controlHead)} is not on the chain`,
    );
  if (!atHead.epochs.has(String(p.dataEpoch)))
    return reject(
      "UNKNOWN_EPOCH",
      "MISSING_DEPENDENCY",
      `epoch ${p.dataEpoch} is not known at the package's head`,
    );
  const sender = atHead.principals.get(toHex(expectedSignerOf(p)));
  if (sender === undefined)
    return reject(
      "UNKNOWN_SENDER",
      "AUTHORIZATION_FAILED",
      "the sender holds no grant at the package's head",
    );
  const signature = verifySignedObject(parsed.signed, sender);
  if (!signature.valid)
    return reject(
      "SIGNATURE",
      "INVALID_SIGNATURE",
      `the package is not signed by its sender (${signature.reason})`,
    );
  const authority = canDistributeKey(atHead, p.sender, p.recipient, p.dataEpoch);
  if (!authority.allowed) return reject("UNAUTHORIZED", "AUTHORIZATION_FAILED", authority.reason);
  return Object.freeze({ kind: "authorized", sender });
}
