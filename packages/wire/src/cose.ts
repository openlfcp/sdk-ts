import {
  bytesEqual,
  type Hash32,
  hash32,
  LfcpError,
  type PrincipalId,
  principalId,
} from "@openlfcp/core";
import { type SigningKeyPair, sha256, verifyEd25519 } from "@openlfcp/crypto";
import {
  type CborValue,
  cborMap,
  decodeDeterministic,
  encode,
  isCborMap,
  isDeterministic,
} from "./cbor/index.js";
import { derivePrincipalId, type PrincipalDescriptor } from "./principal.js";

/**
 * Canonical LFCP COSE_Sign1 (LFCP-WIRE-01 §10).
 *
 * Every persistent LFCP signed object is the untagged array
 * [protected, {}, payload, signature]:
 *
 * - protected: a bstr holding exactly the deterministic map {1: -8, 4: kid},
 *   where kid is the signer's 32-byte Principal ID (§10.1);
 * - unprotected: the empty map (§10.2);
 * - payload: a present bstr with the deterministic CBOR of the LFCP structure (§10.3);
 * - signature: 64-byte Ed25519 over Sig_structure ["Signature1", protected, h'', payload] (§10.4, §10.5).
 *
 * The object ID is SHA-256 of the exact object bytes (§10.6).
 *
 * Signing (`signObject`) and checking received bytes (`parseSignedObject`,
 * `verifySignedObject`) are separate. A parsed object keeps the exact
 * received bytes, and nothing here ever re-encodes them into a "fixed" object.
 *
 * Errors and their wire mapping (ADR 0001):
 * - COSE_MALFORMED and CBOR_* (tags, shape, non-deterministic bytes) → MALFORMED_MESSAGE;
 * - a failed `verifySignedObject` (wrong kid or bad signature) → INVALID_SIGNATURE.
 */

/** COSE algorithm identifier for EdDSA (RFC 9053); the only one LFCP-WIRE-01 allows. */
export const COSE_ALG_EDDSA = -8;
const HEADER_ALG = 1;
const HEADER_KID = 4;
const SIGNATURE_LENGTH = 64;
const EMPTY = new Uint8Array(0);

/** A signer: the Ed25519 key pair and the Principal Descriptor it belongs to. */
export interface Signer {
  readonly key: SigningKeyPair;
  readonly descriptor: PrincipalDescriptor;
}

/** A newly signed object: its exact bytes and its object ID. */
export interface SignedBytes {
  readonly bytes: Uint8Array;
  readonly id: Hash32;
}

/** A received signed object. `bytes` are exactly the received bytes; `id` is their SHA-256. */
export interface SignedObject {
  readonly bytes: Uint8Array;
  readonly protectedBytes: Uint8Array;
  readonly payloadBytes: Uint8Array;
  readonly signature: Uint8Array;
  readonly kid: PrincipalId;
  readonly alg: typeof COSE_ALG_EDDSA;
  readonly id: Hash32;
}

export type VerifyResult =
  | { readonly valid: true }
  | { readonly valid: false; readonly reason: "KID_MISMATCH" | "BAD_SIGNATURE" };

/** Deterministic CBOR of ["Signature1", protected, h'', payload] (§10.5), from the exact header and payload bytes. */
export function sigStructureBytes(
  protectedBytes: Uint8Array,
  payloadBytes: Uint8Array,
): Uint8Array {
  return encode(["Signature1", protectedBytes, EMPTY, payloadBytes]);
}

/** Object ID: SHA-256 of the exact signed-object bytes (§10.6). */
export function objectId(signedObjectBytes: Uint8Array): Hash32 {
  return hash32(sha256(signedObjectBytes));
}

function protectedHeaderBytes(kid: PrincipalId): Uint8Array {
  return encode(
    cborMap([
      [HEADER_ALG, COSE_ALG_EDDSA],
      [HEADER_KID, kid],
    ]),
  );
}

/**
 * Signs deterministic payload bytes into a new canonical LFCP COSE_Sign1.
 * The payload is used exactly as given (never decoded and re-encoded); bytes
 * that are not deterministic CBOR are refused.
 */
export function signObject(payloadBytes: Uint8Array, signer: Signer): SignedBytes {
  const { key, descriptor } = signer;
  if (!bytesEqual(key.publicKey, descriptor.ed25519PublicKey)) {
    throw new LfcpError(
      "COSE_SIGNER_MISMATCH",
      "the signing key does not match the descriptor's Ed25519 public key",
    );
  }
  if (
    !bytesEqual(
      derivePrincipalId(descriptor.ed25519PublicKey, descriptor.x25519PublicKey),
      descriptor.principalId,
    )
  ) {
    throw new LfcpError(
      "PRINCIPAL_ID_MISMATCH",
      "the descriptor's Principal ID does not match its public keys",
    );
  }
  if (!(payloadBytes instanceof Uint8Array) || !isDeterministic(payloadBytes)) {
    throw new LfcpError("CBOR_NON_CANONICAL", "the payload is not deterministic CBOR (§10.3)");
  }
  const protectedBytes = protectedHeaderBytes(descriptor.principalId);
  const signature = key.sign(sigStructureBytes(protectedBytes, payloadBytes));
  const bytes = encode([protectedBytes, cborMap([]), payloadBytes, signature]);
  return Object.freeze({ bytes, id: objectId(bytes) });
}

function malformed(why: string): never {
  throw new LfcpError("COSE_MALFORMED", `not a canonical LFCP COSE_Sign1: ${why}`);
}

/**
 * Parses received signed-object bytes without verifying the signature. It
 * checks the canonical shape and that the object, its protected header and
 * its payload are each deterministic CBOR (§5.2), and keeps every byte
 * string exactly as received.
 */
export function parseSignedObject(bytes: Uint8Array): SignedObject {
  if (bytes.length > 0 && (bytes[0] as number) >> 5 === 6)
    malformed("tagged objects are not allowed (§10)");
  const value = decodeDeterministic(bytes);
  if (!Array.isArray(value) || value.length !== 4) malformed("not a four-element array");
  const [protectedBytes, unprotected, payloadBytes, signature] = value as CborValue[];

  if (!(protectedBytes instanceof Uint8Array)) malformed("protected header is not a byte string");
  const header = decodeDeterministic(protectedBytes);
  if (!isCborMap(header) || header.entries.length !== 2)
    malformed("protected header must be exactly {1: -8, 4: kid}");
  const fields = new Map<unknown, CborValue>(header.entries);
  if (fields.get(HEADER_ALG) !== COSE_ALG_EDDSA) malformed("alg must be -8 (EdDSA)");
  const kid = fields.get(HEADER_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== 32)
    malformed("kid must be a 32-byte Principal ID");

  if (!isCborMap(unprotected) || unprotected.entries.length !== 0)
    malformed("unprotected header must be the empty map");
  if (!(payloadBytes instanceof Uint8Array))
    malformed("payload must be a present byte string (no detached payload)");
  decodeDeterministic(payloadBytes);
  if (!(signature instanceof Uint8Array) || signature.length !== SIGNATURE_LENGTH) {
    malformed(`signature must be ${SIGNATURE_LENGTH} bytes`);
  }

  const exact = Uint8Array.from(bytes);
  return Object.freeze({
    bytes: exact,
    protectedBytes,
    payloadBytes,
    signature,
    kid: principalId(kid),
    alg: COSE_ALG_EDDSA,
    id: objectId(exact),
  });
}

/**
 * Verifies a parsed object against the Principal expected to have signed
 * it. The kid must name that Principal, and the Ed25519 signature must
 * verify over the Sig_structure of the exact received header and payload.
 *
 * Which Principal is expected (the Data Unit actor, the owner, the
 * coordinator, ...) is decided by the object-specific rules in higher
 * layers, not here. A failure surfaces on the wire as INVALID_SIGNATURE.
 */
export function verifySignedObject(
  object: SignedObject,
  expectedSigner: PrincipalDescriptor,
): VerifyResult {
  const expectedId = derivePrincipalId(
    expectedSigner.ed25519PublicKey,
    expectedSigner.x25519PublicKey,
  );
  if (!bytesEqual(object.kid, expectedSigner.principalId) || !bytesEqual(object.kid, expectedId)) {
    return { valid: false, reason: "KID_MISMATCH" };
  }
  const message = sigStructureBytes(object.protectedBytes, object.payloadBytes);
  return verifyEd25519(expectedSigner.ed25519PublicKey, message, object.signature)
    ? { valid: true }
    : { valid: false, reason: "BAD_SIGNATURE" };
}
