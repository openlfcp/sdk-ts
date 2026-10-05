import {
  bytesEqual,
  type DataEpoch,
  dataEpoch,
  type Hash32,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type AgreementKeyPair,
  dekCommitment,
  openDek,
  type ResourceDEK,
  sealDek,
} from "@openlfcp/crypto";
import { canDistributeKey } from "./capability.js";
import { cborMap, encode } from "./cbor/index.js";
import { type Signer, signObject, verifySignedObject } from "./cose.js";
import type { ControlView } from "./epoch.js";
import {
  expectedSignerOf,
  type KeyPackagePayload,
  type Parsed,
  parseKeyPackage,
} from "./objects.js";
import type { PrincipalDescriptor } from "./principal.js";

/**
 * Key Packages (LFCP-WIRE-01 §25): HPKE delivery of a Resource DEK to one
 * recipient Principal, signed by its sender.
 *
 * This module builds and receives packages: the exact §25.1 info and AAD,
 * the §25.2 checks against the Control Chain, and sealing and opening
 * through @openlfcp/crypto HPKE. Opening failures (the package does not open
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
 *   Packages of closed epochs stay valid (§25.2, G-EP6): they are needed
 *   to read history. Otherwise MISSING_DEPENDENCY (§25.2, §26.3);
 * - the sender resolves to a descriptor on the chain: MISSING_DEPENDENCY
 *   (§10.5);
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
  // §10.5: the sender resolves from the whole chain; whether it held
  // key/distribute at the head is the authority check below.
  const sender = view.state.principals.get(toHex(expectedSignerOf(p)));
  if (sender === undefined)
    return reject(
      "UNKNOWN_SENDER",
      "MISSING_DEPENDENCY",
      "no Control Record describes the sender (§10.5)",
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

/** The keys of the Principal a package is opened for: its descriptor and its X25519 key pair. */
export interface KeyPackageRecipient {
  readonly descriptor: PrincipalDescriptor;
  readonly agreement: AgreementKeyPair;
}

export interface SealedKeyPackage {
  /** The exact signed Key Package bytes. */
  readonly bytes: Uint8Array;
  /** §25: the §10.6 object ID of those bytes. */
  readonly packageId: Hash32;
}

/**
 * Creates a Key Package (§25): the DEK sealed with HPKE to the recipient's
 * X25519 key, with the exact §25.1 info and AAD, in a payload signed by the
 * sender. Sealing always uses a fresh ephemeral key. Whether the sender may
 * distribute and the recipient may receive is checked by receivers
 * (verifyKeyPackage); a sender can check it first with canDistributeKey.
 */
export async function sealKeyPackage(options: {
  readonly resourceId: ResourceId;
  readonly epoch: DataEpoch;
  /** The Control Head the package is authorized at. */
  readonly controlHead: Uint8Array;
  readonly recipient: PrincipalDescriptor;
  readonly dek: ResourceDEK;
  readonly signer: Signer;
}): Promise<SealedKeyPackage> {
  const epoch = dataEpoch(options.epoch);
  const { enc, ciphertext } = await sealDek(
    options.recipient.x25519PublicKey,
    options.dek,
    keyPackageHpkeInfo(options.resourceId, epoch, options.recipient.principalId),
    keyPackageHpkeAad(options.resourceId, epoch, options.controlHead),
  );
  const payload = encode(
    cborMap([
      [0, options.resourceId],
      [1, epoch],
      [2, options.recipient.principalId],
      [3, options.controlHead],
      [4, options.signer.descriptor.principalId],
      [5, enc],
      [6, ciphertext],
    ]),
  );
  const signed = signObject(payload, options.signer);
  return Object.freeze({ bytes: signed.bytes, packageId: signed.id });
}

/**
 * Opens a Key Package for its named recipient and checks the DEK against
 * the epoch's commitment (§25, §25.2). The caller passes the keys of the
 * Principal the package names; there is no trying of other keys.
 *
 * Throws KEY_PACKAGE_RECIPIENT_MISMATCH (keys of another Principal),
 * KEY_PACKAGE_OPEN_FAILED or DEK_COMMITMENT_MISMATCH. All are client-local:
 * ignore the package and surface it (ADR 0001 N5).
 */
export async function openKeyPackage(
  parsed: Parsed<KeyPackagePayload>,
  recipient: KeyPackageRecipient,
  expectedCommitment: Uint8Array,
): Promise<ResourceDEK> {
  const p = parsed.payload;
  if (
    !bytesEqual(recipient.descriptor.principalId, p.recipient) ||
    !bytesEqual(recipient.agreement.publicKey, recipient.descriptor.x25519PublicKey)
  )
    throw new LfcpError(
      "KEY_PACKAGE_RECIPIENT_MISMATCH",
      "the keys given are not those of the package's recipient",
    );
  const dek = await openDek(
    recipient.agreement,
    p.hpkeEnc,
    p.hpkeCiphertext,
    keyPackageHpkeInfo(p.resourceId, p.dataEpoch, p.recipient),
    keyPackageHpkeAad(p.resourceId, p.dataEpoch, p.controlHead),
  );
  if (!bytesEqual(dekCommitment(p.resourceId, p.dataEpoch, dek), expectedCommitment))
    throw new LfcpError(
      "DEK_COMMITMENT_MISMATCH",
      "the opened DEK does not match the epoch's commitment",
    );
  return dek;
}

export type ReceivedKeyPackage =
  | { readonly kind: "opened"; readonly dek: ResourceDEK; readonly epoch: DataEpoch }
  | Extract<KeyPackageCheck, { kind: "rejected" }>
  /** Client-local (N5): ignore the package and surface it to the application. */
  | {
      readonly kind: "ignored";
      readonly code:
        | "KEY_PACKAGE_RECIPIENT_MISMATCH"
        | "KEY_PACKAGE_OPEN_FAILED"
        | "DEK_COMMITMENT_MISMATCH";
      readonly message: string;
    };

/**
 * A received Key Package end to end: parse, the §25.2 checks at its head
 * (verifyKeyPackage), then open it for `recipient` and check the DEK
 * against the epoch's commitment from the chain.
 */
export async function receiveKeyPackage(
  view: ControlView,
  bytes: Uint8Array,
  recipient: KeyPackageRecipient,
): Promise<ReceivedKeyPackage> {
  const parsed = parseKeyPackage(bytes);
  const check = verifyKeyPackage(view, parsed);
  if (check.kind === "rejected") return check;
  const commitment = view.state.epochs.get(String(parsed.payload.dataEpoch))?.dekCommitment;
  if (commitment === undefined)
    return reject(
      "UNKNOWN_EPOCH",
      "MISSING_DEPENDENCY",
      "the epoch has no known commitment",
    ) as ReceivedKeyPackage;
  try {
    const dek = await openKeyPackage(parsed, recipient, commitment);
    return Object.freeze({ kind: "opened", dek, epoch: parsed.payload.dataEpoch });
  } catch (e) {
    if (
      e instanceof LfcpError &&
      (e.code === "KEY_PACKAGE_RECIPIENT_MISMATCH" ||
        e.code === "KEY_PACKAGE_OPEN_FAILED" ||
        e.code === "DEK_COMMITMENT_MISMATCH")
    )
      return Object.freeze({ kind: "ignored", code: e.code, message: e.message });
    throw e;
  }
}
