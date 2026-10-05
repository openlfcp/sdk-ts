import { bytesEqual } from "./bytes.js";
import { LfcpError } from "./errors.js";

/**
 * 32-byte LFCP identifiers, as raw bytes.
 *
 * Each kind is a distinct branded Uint8Array, so one kind cannot be passed
 * where another is expected. The constructors check the length and copy the
 * input, so later writes to the caller's buffer cannot change a validated
 * identifier. The returned array is still a Uint8Array: treat it as
 * read-only.
 */
declare const brand: unique symbol;
type Id32<Kind extends string> = Uint8Array & { readonly [brand]: Kind };

/** LFCP-WIRE-01 §6: 32 random bytes. */
export type ResourceId = Id32<"ResourceId">;
/** LFCP-WIRE-01 §7: SHA-256 over the Principal's public keys (derivation is LFCP-014). */
export type PrincipalId = Id32<"PrincipalId">;
/** LFCP-WIRE-01 §5.3: a SHA-256 value encoded as 32 bytes. */
export type Hash32 = Id32<"Hash32">;
/** LFCP-WIRE-01 §13, §10.6: SHA-256 of a Control Record's exact COSE_Sign1 bytes. */
export type ControlRecordId = Id32<"ControlRecordId">;
/** LFCP-WIRE-01 §26, §10.6: SHA-256 of a Data Unit's exact COSE_Sign1 bytes. */
export type DataUnitId = Id32<"DataUnitId">;

export const ID32_LENGTH = 32;

function id32<Kind extends string>(kind: Kind, bytes: Uint8Array): Id32<Kind> {
  if (!(bytes instanceof Uint8Array) || bytes.length !== ID32_LENGTH) {
    const got = bytes instanceof Uint8Array ? `${bytes.length} bytes` : typeof bytes;
    throw new LfcpError(
      "INVALID_LENGTH",
      `${kind} must be exactly ${ID32_LENGTH} bytes, got ${got}`,
    );
  }
  return Uint8Array.from(bytes) as Id32<Kind>;
}

export const resourceId = (bytes: Uint8Array): ResourceId => id32("ResourceId", bytes);
export const principalId = (bytes: Uint8Array): PrincipalId => id32("PrincipalId", bytes);
export const hash32 = (bytes: Uint8Array): Hash32 => id32("Hash32", bytes);
export const controlRecordId = (bytes: Uint8Array): ControlRecordId =>
  id32("ControlRecordId", bytes);
export const dataUnitId = (bytes: Uint8Array): DataUnitId => id32("DataUnitId", bytes);

/** Equality of two identifiers of the same kind. */
export function idEquals<T extends Id32<string>>(a: T, b: T): boolean {
  return bytesEqual(a, b);
}

/**
 * Orders Principal IDs by their raw bytes, compared as unsigned bytes, as
 * LFCP-WIRE-01 §28.2 requires for canonical frontier entries. This is byte
 * order only; it carries no meaning of time, causality or precedence.
 * Returns a negative number, zero or a positive number like Array.sort expects.
 */
export function compareCanonicalFrontierOrder(a: PrincipalId, b: PrincipalId): number {
  for (let i = 0; i < ID32_LENGTH; i += 1) {
    const d = (a[i] as number) - (b[i] as number);
    if (d !== 0) return d;
  }
  return 0;
}
