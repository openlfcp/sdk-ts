import { bytesEqual, fromBase64url, type PrincipalId, toBase64url } from "@openlfcp/core";
import { isValidEd25519PublicKey, sha256 } from "@openlfcp/crypto";

export const IDENTITY_PROFILE_ID = "org.openlfcp.identity.v1";

// IDENTITY-PROFILE-01 §2 inherits SOP §8 without changing its domain.
export { deriveActorId as deriveIdentityActorId } from "../values.js";

export type ResourceRef = string & { readonly __resourceRef: true };

export function isResourceRef(value: unknown): value is ResourceRef {
  if (typeof value !== "string" || value.length !== 43) return false;
  try {
    return fromBase64url(value).length === 32;
  } catch {
    return false;
  }
}

/** W §7 has exactly one deterministic encoding: a3, then 0/1/2 + bstr32. */
export function isIdentityDescriptor(text: string, key: string): boolean {
  try {
    const bytes = fromBase64url(text);
    if (bytes.length !== 106 || bytes[0] !== 0xa3) return false;
    for (let k = 0; k < 3; k++) {
      const at = 1 + 35 * k;
      if (bytes[at] !== k || bytes[at + 1] !== 0x58 || bytes[at + 2] !== 32) return false;
    }
    const id = bytes.subarray(4, 36);
    const ed = bytes.subarray(39, 71);
    const x = bytes.subarray(74, 106);
    const domain = Uint8Array.from("LFCP-PRINCIPAL-v1", (c) => c.charCodeAt(0));
    const input = new Uint8Array(domain.length + 64);
    input.set(domain);
    input.set(ed, domain.length);
    input.set(x, domain.length + 32);
    return (
      key === `p:${toBase64url(id)}` && bytesEqual(id, sha256(input)) && isValidEd25519PublicKey(ed)
    );
  } catch {
    return false;
  }
}

/** Supplied from the verified Identity Resource Control state at control_ref (§2.3). */
export type IdentityWriterClass = "root" | "personal" | "pairing" | "other";

export interface IdentityWriter {
  readonly signer: PrincipalId;
  /** The LFCP Data Unit actor sequence, not the Automerge sequence. */
  readonly actorSeq: bigint | number;
  readonly writerClass: IdentityWriterClass;
}

export interface RosterEntry {
  readonly profile: string;
  readonly endpoints: readonly string[];
  readonly coordinator: string;
  readonly name?: string;
  readonly archived?: boolean;
}

export interface DeviceEntry {
  readonly label: string;
  readonly kind: 0 | 1;
  readonly platform?: string;
  readonly added_at?: string;
  readonly revoked?: boolean;
  /** Safe values are numbers; larger uint64 epochs are lossless bigints. */
  readonly missing_keys?: Readonly<Record<string, readonly IdentityEpoch[]>>;
}

export type IdentityEpoch = bigint | number;

export interface PairingRequest {
  readonly descriptor: string;
  readonly pairing: string;
  readonly label: string;
  readonly kind: 0 | 1;
  readonly scope?: readonly string[];
  readonly platform?: string;
  readonly requested_at?: string;
}

/** Logical §2.1 document; the engine stores strings as ImmutableString, never Text. */
export interface IdentityDocument {
  readonly profile: typeof IDENTITY_PROFILE_ID;
  readonly identity: { readonly root: string };
  readonly roster: Readonly<Record<string, RosterEntry>>;
  readonly devices: Readonly<Record<string, DeviceEntry>>;
  readonly requests: Readonly<Record<string, PairingRequest>>;
  readonly extensions: Readonly<Record<string, unknown>>;
  readonly [unknownKey: string]: unknown;
}
