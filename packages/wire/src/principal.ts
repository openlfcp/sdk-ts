import { bytesEqual, LfcpError, type PrincipalId, principalId } from "@openlfcp/core";
import { isValidEd25519PublicKey, sha256 } from "@openlfcp/crypto";
import {
  type CborMap,
  type CborValue,
  cborMap,
  decodeStrict,
  encode,
  isCborMap,
} from "./cbor/index.js";

/**
 * A Principal Descriptor (LFCP-WIRE-01 §7): the public identity of a
 * Principal. It holds public keys only; private keys stay in
 * @openlfcp/crypto key pairs.
 *
 * CBOR: { 0 => principal-id, 1 => ed25519-public-key, 2 => x25519-public-key },
 * every value a 32-byte byte string.
 */
export interface PrincipalDescriptor {
  readonly principalId: PrincipalId;
  readonly ed25519PublicKey: Uint8Array;
  readonly x25519PublicKey: Uint8Array;
}

const KEY_LENGTH = 32;
const DOMAIN = Uint8Array.from("LFCP-PRINCIPAL-v1", (c) => c.charCodeAt(0));

function invalid(why: string): never {
  throw new LfcpError("INVALID_PRINCIPAL_DESCRIPTOR", `invalid Principal Descriptor: ${why}`);
}

function publicKey(kind: string, bytes: unknown): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_LENGTH)
    invalid(`${kind} must be a ${KEY_LENGTH}-byte byte string`);
  return Uint8Array.from(bytes);
}

/** principal_id = SHA-256(ASCII("LFCP-PRINCIPAL-v1") || ed25519_public_key || x25519_public_key) (§7). */
export function derivePrincipalId(
  ed25519PublicKey: Uint8Array,
  x25519PublicKey: Uint8Array,
): PrincipalId {
  const ed = publicKey("the Ed25519 public key", ed25519PublicKey);
  const x = publicKey("the X25519 public key", x25519PublicKey);
  const input = new Uint8Array(DOMAIN.length + 2 * KEY_LENGTH);
  input.set(DOMAIN, 0);
  input.set(ed, DOMAIN.length);
  input.set(x, DOMAIN.length + KEY_LENGTH);
  return principalId(sha256(input));
}

/** Builds the descriptor for two public keys, deriving the Principal ID. */
export function principalDescriptor(
  ed25519PublicKey: Uint8Array,
  x25519PublicKey: Uint8Array,
): PrincipalDescriptor {
  return Object.freeze({
    principalId: derivePrincipalId(ed25519PublicKey, x25519PublicKey),
    ed25519PublicKey: Uint8Array.from(ed25519PublicKey),
    x25519PublicKey: Uint8Array.from(x25519PublicKey),
  });
}

/** The descriptor for a Principal's key pairs. Only their public keys are read. */
export function principalDescriptorFromKeys(
  signing: { readonly publicKey: Uint8Array },
  agreement: { readonly publicKey: Uint8Array },
): PrincipalDescriptor {
  return principalDescriptor(signing.publicKey, agreement.publicKey);
}

/** The descriptor as a CBOR map, for embedding in larger Wire structures. */
export function principalDescriptorToCbor(descriptor: PrincipalDescriptor): CborMap {
  return cborMap([
    [0, descriptor.principalId],
    [1, descriptor.ed25519PublicKey],
    [2, descriptor.x25519PublicKey],
  ]);
}

/** Deterministic CBOR bytes of the descriptor (§5.2). */
export function encodePrincipalDescriptor(descriptor: PrincipalDescriptor): Uint8Array {
  return encode(principalDescriptorToCbor(descriptor));
}

/**
 * Validates a decoded descriptor: exactly the keys 0, 1 and 2 (the §7 map
 * is closed), each a 32-byte byte string, and a Principal ID equal to the
 * §7 hash of the two public keys ("A verifier MUST recompute the ID
 * whenever a descriptor is received"), and an Ed25519 key that is a
 * canonical point encoding not of small order (§7, §10.5.1).
 */
export function principalDescriptorFromCbor(value: CborValue): PrincipalDescriptor {
  if (!isCborMap(value)) invalid("not a map");
  const fields = new Map<unknown, CborValue>(value.entries);
  if (value.entries.length !== 3 || ![0, 1, 2].every((k) => fields.has(k)))
    invalid("fields must be exactly 0, 1 and 2");
  const id = publicKey("the Principal ID", fields.get(0));
  const descriptor = principalDescriptor(
    publicKey("the Ed25519 public key", fields.get(1)),
    publicKey("the X25519 public key", fields.get(2)),
  );
  if (!bytesEqual(id, descriptor.principalId)) {
    throw new LfcpError(
      "PRINCIPAL_ID_MISMATCH",
      "the Principal ID does not match the descriptor's public keys",
    );
  }
  if (!isValidEd25519PublicKey(descriptor.ed25519PublicKey))
    invalid("the Ed25519 public key is not a canonical point encoding of large order");
  return descriptor;
}

/**
 * Decodes received descriptor bytes. They must be deterministic CBOR
 * (§5.2; CBOR_* errors otherwise) and a valid descriptor.
 */
export function decodePrincipalDescriptor(bytes: Uint8Array): PrincipalDescriptor {
  const value = decodeStrict(bytes);
  if (!bytesEqual(encode(value), bytes)) {
    throw new LfcpError(
      "CBOR_NON_CANONICAL",
      "descriptor bytes are not the deterministic encoding",
    );
  }
  return principalDescriptorFromCbor(value);
}
