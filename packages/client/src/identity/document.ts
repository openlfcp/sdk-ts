import {
  bytesEqual,
  fromBase64url,
  type PrincipalId,
  principalId,
  type ResourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import { type ControlState, type DataProfileCodec, DEVICE_KIND } from "@openlfcp/wire";

/**
 * The Identity Resource's document, as the identity flows see it
 * (IDENTITY-PROFILE-01 §§2–4).
 *
 * @openlfcp/client never binds to the CRDT engine (LFCP-031): the
 * application passes an IdentityDocumentPort, normally backed by
 * @openlfcp/shared-objects' IdentityReplica, which owns admission (§3) and
 * state validation (§4). The flows only produce intents, carry the
 * resulting plaintext in Data Units and read the validated entries back.
 * Nothing in the document confers authority (§4 rule 5): every decision
 * of a flow is taken from a Control Chain.
 */

/** IDENTITY-PROFILE-01's Data Profile identifier. */
export const IDENTITY_PROFILE = "org.openlfcp.identity.v1";

/** §2.3: the writer's class at the Data Unit's control_ref. */
export type IdentityWriterClass = "root" | "personal" | "pairing" | "other";

export interface IdentityAuthor {
  readonly signer: PrincipalId;
  /** The LFCP Data Unit actor sequence of the unit that carries the change. */
  readonly actorSeq: bigint;
  readonly writerClass: IdentityWriterClass;
}

export interface RosterEntryValue {
  readonly profile: string;
  readonly endpoints: readonly string[];
  readonly coordinator: string;
  readonly name?: string;
  readonly archived?: boolean;
}

export interface DeviceEntryValue {
  readonly label: string;
  readonly kind: 0 | 1;
  readonly platform?: string;
  readonly added_at?: string;
  readonly revoked?: boolean;
  readonly missing_keys?: Readonly<Record<string, readonly (bigint | number)[]>>;
}

export interface PairingRequestValue {
  /** base64url of the deterministic CBOR principal descriptor (W §7). */
  readonly descriptor: string;
  /** PrincipalRef of the pairing device that wrote the request. */
  readonly pairing: string;
  readonly label: string;
  readonly kind: 0 | 1;
  readonly scope?: readonly string[];
  readonly platform?: string;
  readonly requested_at?: string;
}

export type IdentityIntent =
  | { readonly intent: "identity.initialize" }
  | { readonly intent: "roster.put"; readonly key: string; readonly entry: RosterEntryValue }
  | { readonly intent: "device.put"; readonly key: string; readonly entry: DeviceEntryValue }
  | { readonly intent: "request.put"; readonly key: string; readonly entry: PairingRequestValue }
  | {
      readonly intent: "roster.delete" | "device.delete" | "request.delete";
      readonly key: string;
    };

export interface IdentityDocumentPort {
  /**
   * The plaintext of one new change by `author` carrying `intents` in one
   * transaction, already applied to the local document. Throws when the
   * document refuses it (the actor sequence is then not used).
   */
  write(author: IdentityAuthor, intents: readonly IdentityIntent[]): Uint8Array;
  /** Applies a received unit's plaintext (§3 admission); false when it is refused or held. */
  receive(plaintext: Uint8Array, author: IdentityAuthor): boolean;
  /** Whether the initial change (§2.2) is admitted. */
  initialized(): boolean;
  /** The valid roster entries (§4 rule 1), by ResourceRef. */
  roster(): ReadonlyMap<string, RosterEntryValue>;
  /** The valid device entries, by PrincipalRef. */
  devices(): ReadonlyMap<string, DeviceEntryValue>;
  /** The valid pairing requests, by PrincipalRef. */
  requests(): ReadonlyMap<string, PairingRequestValue>;
  /**
   * The admitted changes that created, wrote into or deleted `table[key]`,
   * in causal order, with the signer of each (IdentityReplica.origins).
   * Taken from the changes themselves, never inferred from the merged
   * state: §5.3 step 4 accepts a request only when every change that
   * wrote it was signed by the session's pairing device, and the approval
   * journals these change hashes.
   */
  origins(
    table: "roster" | "devices" | "requests",
    key: string,
  ): readonly { readonly hash: string; readonly signer: PrincipalId }[];
  /**
   * Optional (0.5.0): a device entry's `revoked` flag field by field, for
   * a retired entry (§7.1 step 4, §8.2). With it, reconciliation sees every
   * concurrent value of the flag and sets it without writing the entry's
   * other fields, so it never resolves a conflict on them (a concurrent
   * rename). A port without it shows one value per field (`devices()`), and
   * the flag is written with `device.put` of the entry's display fields, as
   * in 0.4. IdentityReplica provides both (`fieldValues`, `write`'s
   * `retire` option).
   */
  readonly retirement?: IdentityRetirementPort;
  /**
   * Optional (0.5.2): the writer's own `missing_keys` hint field by field
   * (§7.1 step 3, §3 AI5), so that writing a hint never writes the entry's
   * label or other fields. Without it, setKeyHints reports `unsupported`.
   * IdentityReplica provides it (`write`'s `hints` option).
   */
  readonly keyHints?: IdentityKeyHintsPort;
}

/** IdentityDocumentPort.keyHints. */
export interface IdentityKeyHintsPort {
  /**
   * The plaintext of one change by `author` that writes, in the author's
   * own entry `devices[<author>]`, `missing_keys[ref] = epochs` for each
   * hint (null or empty: `ref` removed), the field removed when it is left
   * empty, and nothing else.
   */
  write(author: IdentityAuthor, hints: ReadonlyMap<string, readonly bigint[] | null>): Uint8Array;
}

/** IdentityDocumentPort.retirement. */
export interface IdentityRetirementPort {
  /** Every value `devices[key].revoked` holds now: several under concurrent writes, none when absent. */
  revokedValues(key: string): readonly unknown[];
  /**
   * Like IdentityDocumentPort.write, the plaintext of one change by
   * `author`: `intents` in order (possibly none), then `revoked = true` in
   * each existing entry `devices[key]` of `retire`, no other field of those
   * entries written.
   */
  write(
    author: IdentityAuthor,
    intents: readonly IdentityIntent[],
    retire: readonly string[],
  ): Uint8Array;
}

/** A passthrough Data Unit codec: the port produces and consumes the plaintext. */
export const identityPlaintextCodec: DataProfileCodec<Uint8Array> = Object.freeze({
  dataProfile: IDENTITY_PROFILE,
  encode: (plaintext: Uint8Array) => plaintext,
  decode: (plaintext: Uint8Array) => plaintext,
});

/** ResourceRef (§2.1): unpadded base64url of the 32-byte Resource ID. */
export const resourceRef = (id: ResourceId): string => toBase64url(id);

/** PrincipalRef (SOP §27): "p:" + unpadded base64url of the Principal ID. */
export const principalRefOf = (id: PrincipalId): string => `p:${toBase64url(id)}`;

/** The Principal ID of a PrincipalRef; undefined when it is malformed. */
export function principalOfRef(ref: string): PrincipalId | undefined {
  if (!ref.startsWith("p:") || ref.length !== 45) return undefined;
  try {
    return principalId(fromBase64url(ref.slice(2)));
  } catch {
    return undefined;
  }
}

/**
 * §2.3: the writer class of `signer` from the Identity Resource's Control
 * state at the unit's control_ref; `root` is the Genesis owner.
 */
export function identityWriterClass(
  state: ControlState,
  root: PrincipalId,
  signer: PrincipalId,
): IdentityWriterClass {
  if (bytesEqual(signer, root)) return "root";
  const d = state.devices.get(toHex(signer));
  if (d === undefined || !bytesEqual(d.root, root)) return "other";
  if (d.kind === DEVICE_KIND.PERSONAL) return "personal";
  if (d.kind === DEVICE_KIND.PAIRING) return "pairing";
  return "other";
}
