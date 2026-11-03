// Synthetic identity material for @openlfcp/wire unit tests (IDENTITY-01,
// LFCP-WIRE-01 §7.3). The inputs follow sdk-rs
// crates/lfcp/tests/identity_wire_codecs.rs so both SDKs judge the same
// bytes: Principal n has the Ed25519 seed [n; 32] and the X25519 key
// [n + 100; 32], a device's serial is [n; 16], the Resource is [77; 32].
// Not values of a published vector (LFCP-04-403 publishes those).

import { LfcpError, type ResourceId, resourceId } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { type CborValue, cborMap, decodeStrict, encode, isCborMap } from "../src/cbor/index.js";
import {
  type CertificateChain,
  certificateChain,
  DEVICE_KIND,
  type DeviceCertificate,
  type DeviceCertificatePayload,
  type DeviceKind,
  principalDescriptorFromKeys,
  type Signer,
  signDeviceCertificate,
  signObject,
} from "../src/index.js";

const fill = (n: number, length = 32): Uint8Array => new Uint8Array(length).fill(n);

const cache = new Map<number, Signer>();
/** Principal n (Rust `keys(n)`). */
export function keys(n: number): Signer {
  let s = cache.get(n);
  if (s === undefined) {
    const key = importSigningKey(fill(n));
    s = { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(fill(n + 100))) };
    cache.set(n, s);
  }
  return s;
}
export const id = (n: number) => keys(n).descriptor.principalId;
export const ROOT = keys(1);
export const RESOURCE: ResourceId = resourceId(fill(77));
export const rid = (n: number): ResourceId => resourceId(fill(n));

export function payload(
  device: number,
  kind: DeviceKind,
  mask: readonly (number | bigint)[],
  scope: readonly ResourceId[] = [],
  root = id(1),
): DeviceCertificatePayload {
  return {
    root,
    device: keys(device).descriptor,
    kind,
    mask: mask.map(BigInt),
    scope,
    serial: fill(device, 16),
  };
}
export const personal = (device: number, mask: readonly (number | bigint)[]) =>
  payload(device, DEVICE_KIND.PERSONAL, mask);
export const cert = (p: DeviceCertificatePayload, signer: number): DeviceCertificate =>
  signDeviceCertificate(p, keys(signer));
export const chain = (certs: readonly DeviceCertificate[], root = id(1)): CertificateChain =>
  certificateChain(certs, root);

/** Signs any CBOR value as a canonical COSE_Sign1 (bypasses the writer rules). */
export const signed = (value: CborValue, signer: number): Uint8Array =>
  signObject(encode(value), keys(signer)).bytes;

/** The certificate with its first signature byte flipped. */
export function brokenSignature(c: DeviceCertificate): Uint8Array {
  const object = decodeStrict(c.signed.bytes) as CborValue[];
  const signature = Uint8Array.from(c.signed.signature);
  signature[0] = (signature[0] as number) ^ 1;
  return encode([
    object[0] as CborValue,
    object[1] as CborValue,
    object[2] as CborValue,
    signature,
  ]);
}

export function replace(value: CborValue, index: number, v: CborValue): CborValue {
  const list = [...(value as readonly CborValue[])];
  list[index] = v;
  return list;
}

/** A map with `key` removed, or set to `v`. */
export function field(value: CborValue, key: number, v?: CborValue): CborValue {
  if (!isCborMap(value)) throw new Error("not a map");
  const entries = value.entries.filter(([k]) => k !== key);
  return cborMap(v === undefined ? entries : [...entries, [key, v]]);
}

/** LFCP-WIRE-01 §62 code of an error thrown while decoding a received object. */
export function wireOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (!(e instanceof LfcpError)) throw e;
    if (e.code.startsWith("CBOR_")) return "MALFORMED_MESSAGE";
    const map: Record<string, string> = {
      COSE_MALFORMED: "MALFORMED_MESSAGE",
      INVALID_STRUCTURE: "MALFORMED_MESSAGE",
      INVALID_PRINCIPAL_DESCRIPTOR: "MALFORMED_MESSAGE",
      PRINCIPAL_ID_MISMATCH: "MALFORMED_MESSAGE",
      UNSUPPORTED_VALUE: "INVALID_CONTROL_CHAIN",
    };
    return map[e.code] ?? `UNMAPPED:${e.code}`;
  }
  return "ACCEPTED";
}

/** The Rust deep_chain: 5 <- 4 <- 3 <- 2 <- root, every issuer managing. */
export const deepChain = (managingLeaf: boolean): DeviceCertificate[] => [
  cert(personal(5, managingLeaf ? [1, 2, 12] : [1, 2]), 4),
  cert(personal(4, [1, 2, 12]), 3),
  cert(personal(3, [1, 2, 12]), 2),
  cert(personal(2, [1, 2, 12]), 1),
];
