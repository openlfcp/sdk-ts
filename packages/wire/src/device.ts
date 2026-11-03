import {
  bytesEqual,
  type Hash32,
  hash32,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import { isValidEd25519PublicKey, sha256 } from "@openlfcp/crypto";
import { type CborValue, decodeStrict, encode } from "./cbor/index.js";
import {
  parseSignedObject,
  type SignedObject,
  type Signer,
  signObject,
  verifySignedObject,
} from "./cose.js";
import { scanDeviceCertificate } from "./device-scan.js";
import { invalid } from "./fields.js";
import {
  derivePrincipalId,
  type PrincipalDescriptor,
  principalDescriptorFromCbor,
  principalDescriptorToCbor,
} from "./principal.js";

/**
 * Device Certificates and certificate chains (LFCP-WIRE-01 §7.2, §7.3,
 * IDENTITY-01): the codec, the structural rules, and `verifyChain` with
 * the class order of §62 (structure, dependencies, signatures, authority
 * and state).
 *
 * Structure only decides what can be decided from the bytes: every
 * failure of §7.3 rules 1–5, (c1), (c5) and (c7) is INVALID_STRUCTURE
 * (MALFORMED_MESSAGE on the wire), thrown while decoding. The state
 * questions of §7.3 step 4.2–4.4 (roles, bindings, revocations) are asked
 * through the read-only `ChainStateChecks`; this module stores no state
 * and applies no transition.
 *
 * Unknown mask codes (and 9, 11) are kept as received, in received order,
 * and never promoted to abilities. Exact certificate bytes are kept: a
 * chain re-encodes to the byte strings it was read from.
 */

/** §7.3 rule 1: the domain and version label, payload element 0. */
export const DEVICE_CERT_LABEL = "LFCP-DEVICE-CERT-v1";
/** §7.3: `certificate-chain = [1*4 bstr]`. */
export const MAX_CHAIN_LENGTH = 4;
/** §7.3 (c7): a chain whose leaf lists `device/manage` has at most three certificates. */
export const MAX_MANAGING_CHAIN_LENGTH = 3;
/** §7.3 rule 4: `device-mask = [1*32 uint]`. */
export const MAX_MASK_ENTRIES = 32;
/** §7.3: `resource-scope = [*64 resource-id]`. */
export const MAX_SCOPE_ENTRIES = 64;
/** §7.3: `bstr .size 16`, the serial. */
export const SERIAL_LENGTH = 16;

/** §17.1 codes that have meaning only inside a Device Certificate mask. */
export const DEVICE_ABILITY = Object.freeze({
  /** `device/manage`: may sign Device Certificates and issue device records for its root. */
  DEVICE_MANAGE: 12n,
  /** `owner/act`: in a Resource its root owns, holds every standard ability. */
  OWNER_ACT: 13n,
});

/** §7.2 kinds: 0 personal, 1 service, 2 pairing. 3 and above are reserved. */
export const DEVICE_KIND = Object.freeze({ PERSONAL: 0, SERVICE: 1, PAIRING: 2 } as const);
export type DeviceKind = (typeof DEVICE_KIND)[keyof typeof DEVICE_KIND];

/** `device-certificate-payload` (§7.3). */
export interface DeviceCertificatePayload {
  /** Field 1: the root the device acts for. */
  readonly root: PrincipalId;
  /** Field 2: the device (self-certifying, §7). */
  readonly device: PrincipalDescriptor;
  readonly kind: DeviceKind;
  /** Field 4: 1–32 distinct codes, in received order. Unknown codes confer nothing. */
  readonly mask: readonly bigint[];
  /** Field 5: distinct Resource IDs, subject to the kind rules. */
  readonly scope: readonly ResourceId[];
  /** Field 6: 16 random bytes; no order, no time. */
  readonly serial: Uint8Array;
}

/** A Device Certificate: the exact signed object and its payload. */
export interface DeviceCertificate {
  readonly signed: SignedObject;
  readonly payload: DeviceCertificatePayload;
  /** §7.3 rule 6: the §10.6 object ID of the exact COSE bytes. */
  readonly id: Hash32;
  /** §7.3 rule 6: SHA-256 of the exact payload bytes; what a pairing approval commits to. */
  readonly payloadDigest: Hash32;
}

/** A chain well-formed for `root` (§7.3 (c1), (c5), (c7)): leaf first, issued by the root last. */
export interface CertificateChain {
  readonly root: PrincipalId;
  readonly certificates: readonly DeviceCertificate[];
  readonly leaf: DeviceCertificate;
  /** The devices that issued inside the chain (`c_1 .. c_{n-1}`), leaf's issuer first. */
  readonly issuers: readonly PrincipalId[];
}

// ---------------------------------------------------------------------------
// Payload

const fail = (why: string): never => invalid("device-certificate-payload", why);

const UINT64_MAX = 2n ** 64n - 1n;

const hasCode = (mask: readonly bigint[], code: bigint): boolean => mask.includes(code);

/** Distinct members, compared by value (Resource IDs as bytes). */
function repeats<T>(list: readonly T[], key: (item: T) => string | bigint): boolean {
  return new Set(list.map(key)).size !== list.length;
}

/**
 * §7.3 rules 2–5 on a payload: a 32-byte root, a valid device descriptor
 * (§7) that is not the root; a mask of 1–32
 * distinct unsigned 64-bit codes, with `1` and `2` whenever it lists `12`; at most 64
 * distinct scope entries; and the kind rules for scope and mask. Throws
 * INVALID_STRUCTURE. Writers and readers apply the same rules.
 */
export function checkDeviceCertificatePayload(p: DeviceCertificatePayload): void {
  if (!(p.root instanceof Uint8Array) || p.root.length !== 32)
    fail("the root must be a 32-byte Principal ID");
  // Rule 2: the descriptor as §7 requires (recomputed ID, canonical
  // Ed25519 point of large order), so that what passes here can be signed.
  const d = p.device;
  try {
    if (!bytesEqual(derivePrincipalId(d.ed25519PublicKey, d.x25519PublicKey), d.principalId))
      fail("the device descriptor's ID is not the §7 hash of its keys (§7.3 rule 2)");
  } catch (e) {
    if (e instanceof LfcpError && e.code === "INVALID_STRUCTURE") throw e;
    fail("the device descriptor's keys are not 32-byte keys (§7.3 rule 2)");
  }
  if (!isValidEd25519PublicKey(d.ed25519PublicKey))
    fail("the device's Ed25519 key is not a canonical point of large order (§7.3 rule 2)");
  if (bytesEqual(p.root, p.device.principalId)) fail("the device is the root (§7.3 rule 2)");
  if (p.kind !== 0 && p.kind !== 1 && p.kind !== 2) fail("kind must be 0, 1 or 2 (§7.3 rule 3)");
  if (p.mask.length < 1 || p.mask.length > MAX_MASK_ENTRIES)
    fail(`the mask must hold 1 to ${MAX_MASK_ENTRIES} codes (§7.3 rule 4)`);
  if (!p.mask.every((c) => typeof c === "bigint" && c >= 0n && c <= UINT64_MAX))
    fail("every mask code must be an unsigned 64-bit integer (§7.3)");
  if (repeats(p.mask, (c) => c)) fail("the mask repeats a code (§7.3 rule 4)");
  const manage = hasCode(p.mask, DEVICE_ABILITY.DEVICE_MANAGE);
  if (manage && !(hasCode(p.mask, 1n) && hasCode(p.mask, 2n)))
    fail("a mask that lists 12 must list 1 and 2 (§7.3 rule 4)");
  if (p.scope.length > MAX_SCOPE_ENTRIES)
    fail(`the scope holds more than ${MAX_SCOPE_ENTRIES} Resources (§7.3)`);
  if (!p.scope.every((r) => r instanceof Uint8Array && r.length === 32))
    fail("every scope entry must be a 32-byte Resource ID (§7.3)");
  if (repeats(p.scope, toHex)) fail("the scope repeats a Resource (§7.3 rule 5)");
  if (!(p.serial instanceof Uint8Array) || p.serial.length !== SERIAL_LENGTH)
    fail(`the serial must be ${SERIAL_LENGTH} bytes (§7.3)`);
  switch (p.kind) {
    case DEVICE_KIND.PERSONAL:
      if (p.scope.length !== 0) fail("a personal device has an empty scope (§7.3 rule 5)");
      return;
    case DEVICE_KIND.SERVICE:
      if (p.scope.length === 0) fail("a service device lists 1 to 64 Resources (§7.3 rule 5)");
      if (manage || hasCode(p.mask, DEVICE_ABILITY.OWNER_ACT))
        fail("a service device never lists 12 or 13 (§7.3 rule 5)");
      return;
    case DEVICE_KIND.PAIRING:
      if (p.scope.length !== 1) fail("a pairing device lists exactly one Resource (§7.3 rule 5)");
      if (!p.mask.every((c) => c === 1n || c === 2n))
        fail("a pairing device's mask is a subset of {1, 2} (§7.3 rule 5)");
      return;
  }
}

function uintOf(value: CborValue | undefined): bigint | undefined {
  return (typeof value === "number" || typeof value === "bigint") && value >= 0
    ? BigInt(value)
    : undefined;
}

/**
 * Decodes `device-certificate-payload` (§7.3): a seven-element array
 * labelled `LFCP-DEVICE-CERT-v1`, then rules 2–5. Array lengths are
 * checked before their entries are decoded.
 */
export function deviceCertificatePayloadFromCbor(value: CborValue): DeviceCertificatePayload {
  if (!Array.isArray(value)) fail("not an array (§7.3 rule 1)");
  const fields = value as readonly CborValue[];
  if (fields.length !== 7) fail("must have seven elements (§7.3 rule 1)");
  const [label, root, device, kind, mask, scope, serial] = fields;
  if (label !== DEVICE_CERT_LABEL) fail(`element 0 must be "${DEVICE_CERT_LABEL}" (§7.3 rule 1)`);
  if (!(root instanceof Uint8Array) || root.length !== 32)
    fail("field 1 must be a 32-byte Principal ID");
  const k = uintOf(kind);
  if (k === undefined || k > 2n) fail("field 3 must be 0, 1 or 2 (§7.3 rule 3)");
  if (!Array.isArray(mask)) fail("field 4 must be an array");
  const maskList = mask as readonly CborValue[];
  if (maskList.length < 1 || maskList.length > MAX_MASK_ENTRIES)
    fail(`field 4 must hold 1 to ${MAX_MASK_ENTRIES} codes (§7.3 rule 4)`);
  if (!Array.isArray(scope)) fail("field 5 must be an array");
  const scopeList = scope as readonly CborValue[];
  if (scopeList.length > MAX_SCOPE_ENTRIES)
    fail(`field 5 must hold at most ${MAX_SCOPE_ENTRIES} Resource IDs (§7.3)`);
  if (!(serial instanceof Uint8Array) || serial.length !== SERIAL_LENGTH)
    fail(`field 6 must be ${SERIAL_LENGTH} bytes`);
  let descriptor: PrincipalDescriptor;
  try {
    descriptor = principalDescriptorFromCbor(device as CborValue);
  } catch (e) {
    return fail(`field 2 is not a valid Principal Descriptor (§7.3 rule 2): ${String(e)}`);
  }
  const payload: DeviceCertificatePayload = Object.freeze({
    root: principalId(Uint8Array.from(root as Uint8Array)),
    device: descriptor,
    kind: Number(k) as DeviceKind,
    mask: Object.freeze(
      maskList.map((c) => uintOf(c) ?? fail("field 4 must hold unsigned integers only")),
    ),
    scope: Object.freeze(
      scopeList.map((r) =>
        r instanceof Uint8Array && r.length === 32
          ? resourceId(Uint8Array.from(r))
          : fail("field 5 must hold 32-byte Resource IDs only"),
      ),
    ),
    serial: Uint8Array.from(serial as Uint8Array),
  });
  checkDeviceCertificatePayload(payload);
  return payload;
}

/** The payload as the §7.3 array. */
export function deviceCertificatePayloadToCbor(p: DeviceCertificatePayload): CborValue {
  return [
    DEVICE_CERT_LABEL,
    p.root,
    principalDescriptorToCbor(p.device),
    p.kind,
    [...p.mask],
    [...p.scope],
    p.serial,
  ];
}

/** Deterministic CBOR of a payload that satisfies §7.3 rules 1–5 (INVALID_STRUCTURE otherwise). */
export function encodeDeviceCertificatePayload(p: DeviceCertificatePayload): Uint8Array {
  checkDeviceCertificatePayload(p);
  return encode(deviceCertificatePayloadToCbor(p));
}

/**
 * §7.3 rule 6: the certificate payload digest, SHA-256 of the payload's
 * deterministic CBOR. Computed before the certificate exists, it is what a
 * `DEVICE_REVOKE` with reason 3 commits to (§17.5, invariant N9).
 */
export const deviceCertificatePayloadDigest = (p: DeviceCertificatePayload): Hash32 =>
  hash32(sha256(encodeDeviceCertificatePayload(p)));

/** A fresh random serial (§7.3 field 6, §5.4). */
export const newDeviceCertificateSerial = (): Uint8Array => secureRandom(SERIAL_LENGTH);

// ---------------------------------------------------------------------------
// Certificate

/**
 * Parses a Device Certificate from its exact COSE bytes: the canonical
 * COSE_Sign1 shape with the §5.2 canonical-bytes check of its protected
 * header and payload (cose.ts), then the payload rules. The signature is
 * not verified here; its signer is decided by chain position (§7.3 (c2)).
 */
export function parseDeviceCertificate(bytes: Uint8Array): DeviceCertificate {
  // Bounds first, on the raw bytes: nothing is decoded or copied before them.
  scanDeviceCertificate(bytes);
  const signed = parseSignedObject(bytes);
  const payload = deviceCertificatePayloadFromCbor(decodeStrict(signed.payloadBytes));
  return Object.freeze({
    signed,
    payload,
    id: signed.id,
    payloadDigest: hash32(sha256(signed.payloadBytes)),
  });
}

/**
 * Signs a Device Certificate. `signer` is the root or a managing device of
 * the root; which one is valid is decided by the chain it is placed in.
 * The payload must satisfy §7.3 rules 1–5 (INVALID_STRUCTURE otherwise).
 */
export function signDeviceCertificate(
  payload: DeviceCertificatePayload,
  signer: Signer,
): DeviceCertificate {
  return parseDeviceCertificate(signObject(encodeDeviceCertificatePayload(payload), signer).bytes);
}

// ---------------------------------------------------------------------------
// Chain structure

const chainFail = (why: string): never => invalid("certificate-chain", why);

/**
 * (c1) every certificate names `root`; (c5) no device twice and none is
 * the root (rule 2 already refuses device = own root); (c7) a managing
 * leaf has at most three certificates. Payloads are leaf first.
 */
function checkChainStructure(payloads: readonly DeviceCertificatePayload[], root: PrincipalId) {
  if (payloads.length < 1 || payloads.length > MAX_CHAIN_LENGTH)
    chainFail(`must hold 1 to ${MAX_CHAIN_LENGTH} certificates (§7.3 (c1))`);
  const seen = new Set<string>();
  for (const p of payloads) {
    if (!bytesEqual(p.root, root)) chainFail("a certificate names another root (§7.3 (c1))");
    const id = toHex(p.device.principalId);
    if (seen.has(id) || bytesEqual(p.device.principalId, root))
      chainFail("a device appears twice, or the root appears as a device (§7.3 (c5))");
    seen.add(id);
  }
  const leaf = payloads[0] as DeviceCertificatePayload;
  if (
    hasCode(leaf.mask, DEVICE_ABILITY.DEVICE_MANAGE) &&
    payloads.length > MAX_MANAGING_CHAIN_LENGTH
  )
    chainFail(`a managing leaf has at most ${MAX_MANAGING_CHAIN_LENGTH} certificates (§7.3 (c7))`);
}

function chainOf(certificates: readonly DeviceCertificate[], root: PrincipalId): CertificateChain {
  checkChainStructure(
    certificates.map((c) => c.payload),
    root,
  );
  return Object.freeze({
    root: principalId(Uint8Array.from(root)),
    certificates: Object.freeze([...certificates]),
    leaf: certificates[0] as DeviceCertificate,
    issuers: Object.freeze(certificates.slice(1).map((c) => c.payload.device.principalId)),
  });
}

/** Builds a chain (leaf first) for `root`, applying (c1), (c5) and (c7). INVALID_STRUCTURE otherwise. */
export const certificateChain = (
  certificates: readonly DeviceCertificate[],
  root: PrincipalId,
): CertificateChain => chainOf(certificates, root);

/**
 * Decodes a received `certificate-chain` for `root`: an array of one to
 * four byte strings (checked before any certificate is parsed), each a
 * Device Certificate, then (c1), (c5), (c7). Every certificate is parsed
 * in full before any chain rule, so every structural failure of every
 * certificate is reported as structure (§62 class 1).
 */
export function certificateChainFromCbor(value: CborValue, root: PrincipalId): CertificateChain {
  if (!Array.isArray(value)) chainFail("not an array");
  const list = value as readonly CborValue[];
  if (list.length < 1 || list.length > MAX_CHAIN_LENGTH)
    chainFail(`must hold 1 to ${MAX_CHAIN_LENGTH} certificates`);
  if (!list.every((c) => c instanceof Uint8Array)) chainFail("must hold byte strings only");
  return chainOf((list as readonly Uint8Array[]).map(parseDeviceCertificate), root);
}

/** The chain as the §7.3 array of exact certificate bytes (never re-encoded). */
export const certificateChainToCbor = (chain: CertificateChain): CborValue =>
  chain.certificates.map((c) => c.signed.bytes);

// ---------------------------------------------------------------------------
// verifyChain

/** The rule that decided a chain verdict, for diagnostics and tests. */
export type DeviceChainRule =
  /** (c1): the chain is for another root than the one the record names. */
  | "c1-root"
  /** (c1), (c5), (c7) or rules 1–5 on a prospective certificate (preflight). */
  | "structure"
  /** §7.3 step 2: the root's descriptor is not available. */
  | "root-descriptor"
  /** (c2): a certificate's kid is not the Principal its position requires. */
  | "c2-kid"
  /** (c2): a certificate's signature does not verify. */
  | "c2-signature"
  /** (c3): an issuer is not a managing personal device. */
  | "c3"
  /** (c4): a mask is not a subset of its issuer's mask. */
  | "c4"
  /** (c6): a pairing leaf whose scope does not list the Resource. */
  | "c6"
  /** step 4.2: `roles[R]` is `device`. */
  | "root-role"
  /** step 4.3: a device's role or existing binding conflicts with this chain (N8). */
  | "binding"
  /** step 4.4: `(R, E)` is revoked. */
  | "revoked";

const WIRE_OF: Readonly<Record<DeviceChainRule, ChainWireCode>> = {
  "c1-root": "MALFORMED_MESSAGE",
  structure: "MALFORMED_MESSAGE",
  "root-descriptor": "MISSING_DEPENDENCY",
  "c2-kid": "INVALID_SIGNATURE",
  "c2-signature": "INVALID_SIGNATURE",
  c3: "AUTHORIZATION_FAILED",
  c4: "AUTHORIZATION_FAILED",
  c6: "AUTHORIZATION_FAILED",
  "root-role": "AUTHORIZATION_FAILED",
  binding: "AUTHORIZATION_FAILED",
  revoked: "AUTHORIZATION_FAILED",
};

export type ChainWireCode =
  | "MALFORMED_MESSAGE"
  | "MISSING_DEPENDENCY"
  | "INVALID_SIGNATURE"
  | "AUTHORIZATION_FAILED";

/** A refusal: the first failing rule in §62 class order and its wire code. */
export interface ChainRefusal {
  readonly valid: false;
  readonly rule: DeviceChainRule;
  readonly wireCode: ChainWireCode;
  readonly reason: string;
}

/** An accepted chain (§7.3 result): evidence for the state validator, not a transition. */
export interface VerifiedChain {
  readonly valid: true;
  readonly chain: CertificateChain;
  /** The leaf's payload: its descriptor, kind, mask and scope. */
  readonly leaf: DeviceCertificatePayload;
  readonly leafId: Hash32;
  readonly issuers: readonly PrincipalId[];
  /** False only for a kind-1 leaf whose scope does not list the Resource (bound, never registered). */
  readonly inScope: boolean;
  /** Every certificate's payload, leaf first: the bindings to record (§79). */
  readonly bindings: readonly DeviceCertificatePayload[];
}

const refuse = (rule: DeviceChainRule, reason: string): ChainRefusal =>
  Object.freeze({ valid: false, rule, wireCode: WIRE_OF[rule], reason });

/**
 * Read-only view of the previous Control state for §7.3 step 4.2–4.4.
 * Mask and scope are compared as sets; serial and issuer may differ.
 */
export interface ChainStateChecks {
  /** Step 4.2: `roles[root]` is absent or `non-device`. */
  rootAllowed(root: PrincipalId): boolean;
  /**
   * Step 4.3: `roles[device]` is absent or `device`, and an existing
   * `devices[device]` has this root and the certificate's kind, mask and scope.
   */
  bindingMatches(certificate: DeviceCertificatePayload): boolean;
  /** Step 4.4: whether `(root, device)` is in `revoked`. */
  isRevoked(root: PrincipalId, device: PrincipalId): boolean;
}

/** The empty state of a Genesis (§15: `S = empty`); nothing is bound or revoked. */
export const EMPTY_CHAIN_STATE: ChainStateChecks = Object.freeze({
  rootAllowed: () => true,
  bindingMatches: () => true,
  isRevoked: () => false,
});

/**
 * (c2): the last certificate's kid must be the root, so a root descriptor
 * for another Principal cannot verify it: INVALID_SIGNATURE, as in sdk-rs.
 */
function rootDescriptorMismatch(
  root: PrincipalId,
  descriptor: PrincipalDescriptor,
): ChainRefusal | undefined {
  return bytesEqual(descriptor.principalId, root)
    ? undefined
    : refuse("c2-kid", "the root descriptor is not the chain's root (c2)");
}

function verifySignatures(
  certificates: readonly DeviceCertificate[],
  rootDescriptor: PrincipalDescriptor,
): ChainRefusal | undefined {
  for (const [i, c] of certificates.entries()) {
    const signer = certificates[i + 1]?.payload.device ?? rootDescriptor;
    const v = verifySignedObject(c.signed, signer);
    if (!v.valid)
      return v.reason === "KID_MISMATCH"
        ? refuse("c2-kid", `certificate ${i} is not signed by the Principal (c2) requires`)
        : refuse("c2-signature", `certificate ${i}'s signature does not verify (c2)`);
  }
  return undefined;
}

/** (c3), (c4), (c6) for every link, each rule over the whole chain before the next. */
function checkAuthority(
  payloads: readonly DeviceCertificatePayload[],
  resource: ResourceId,
): ChainRefusal | boolean {
  for (const issuer of payloads.slice(1))
    if (issuer.kind !== DEVICE_KIND.PERSONAL || !hasCode(issuer.mask, DEVICE_ABILITY.DEVICE_MANAGE))
      return refuse("c3", "an issuer is not a personal device with device/manage (c3)");
  for (const [i, child] of payloads.entries()) {
    const issuer = payloads[i + 1];
    if (issuer !== undefined && !child.mask.every((c) => hasCode(issuer.mask, c)))
      return refuse("c4", "a mask is not a subset of its issuer's mask (c4)");
  }
  const leaf = payloads[0] as DeviceCertificatePayload;
  const lists = leaf.scope.some((r) => bytesEqual(r, resource));
  if (leaf.kind === DEVICE_KIND.PAIRING && !lists)
    return refuse("c6", "a pairing leaf whose scope does not list this Resource (c6)");
  return leaf.kind !== DEVICE_KIND.SERVICE || lists;
}

/**
 * §7.3 step 3 only (class 4): (c2) for every certificate, leaf first.
 * A validator of a record that embeds a chain resolves every dependency
 * of the record (outer issuer and chain root) before any signature, so
 * this is separate from the descriptor lookup (§62).
 */
export function verifyChainSignatures(
  chain: CertificateChain,
  rootDescriptor: PrincipalDescriptor,
): ChainRefusal | { readonly valid: true } {
  return (
    rootDescriptorMismatch(chain.root, rootDescriptor) ??
    verifySignatures(chain.certificates, rootDescriptor) ?? { valid: true }
  );
}

/** §7.3 step 4.1 (class 5): (c3), (c4), (c6). `inScope` as in VerifiedChain. */
export function checkChainAuthority(
  chain: CertificateChain,
  resource: ResourceId,
): ChainRefusal | { readonly valid: true; readonly inScope: boolean } {
  const r = checkAuthority(
    chain.certificates.map((c) => c.payload),
    resource,
  );
  return typeof r === "boolean" ? { valid: true, inScope: r } : r;
}

/** §7.3 step 4.2–4.4 (class 5): the root's role, then every binding, then every revocation. */
export function checkChainState(
  chain: CertificateChain,
  state: ChainStateChecks,
): ChainRefusal | { readonly valid: true } {
  if (!state.rootAllowed(chain.root))
    return refuse("root-role", "the root is bound as a device in this Resource (step 4.2)");
  for (const c of chain.certificates)
    if (!state.bindingMatches(c.payload))
      return refuse(
        "binding",
        "a device's role or binding conflicts with this chain (step 4.3, N8)",
      );
  for (const c of chain.certificates)
    if (state.isRevoked(chain.root, c.payload.device.principalId))
      return refuse("revoked", "a device of the chain is revoked for this root (step 4.4)");
  return { valid: true };
}

/**
 * `verifyChain(chain, R, R_descriptor, S)` (§7.3) in Resource `resource`:
 * one pass of the §62 classes. Structure was checked when the chain was
 * decoded; here (c1) is checked against `root`, then the root descriptor
 * (MISSING_DEPENDENCY when undefined), then every signature, then (c3),
 * (c4), (c6), then the state predicates. Pure; reads no clock.
 */
export function verifyChain(
  chain: CertificateChain,
  root: PrincipalId,
  rootDescriptor: PrincipalDescriptor | undefined,
  resource: ResourceId,
  state: ChainStateChecks,
): VerifiedChain | ChainRefusal {
  if (!bytesEqual(chain.root, root)) return refuse("c1-root", "the chain is for another root (c1)");
  if (rootDescriptor === undefined)
    return refuse("root-descriptor", "the root's descriptor is not known (step 2)");
  const signatures = verifyChainSignatures(chain, rootDescriptor);
  if (!signatures.valid) return signatures;
  const authority = checkChainAuthority(chain, resource);
  if (!authority.valid) return authority;
  const s = checkChainState(chain, state);
  if (!s.valid) return s;
  return Object.freeze({
    valid: true,
    chain,
    leaf: chain.leaf.payload,
    leafId: chain.leaf.id,
    issuers: chain.issuers,
    inScope: authority.inScope,
    bindings: Object.freeze(chain.certificates.map((c) => c.payload)),
  });
}

/**
 * Checks a prospective leaf before it is signed, against the issuing
 * device's chain (`issuers`, leaf-first; empty when the root issues): the
 * structure of the chain the leaf would form, the root descriptor, the
 * issuers' signatures, then (c3), (c4), (c6). Lets a managing installation
 * refuse an issuance (managing depth 4, an empty service scope) before it
 * consumes a pairing session (§7.3 N9, IDENTITY-PROFILE-01 §5). Current
 * state (standing, activity) is the caller's to check.
 */
export function preflightIssuance(
  leaf: DeviceCertificatePayload,
  issuers: readonly DeviceCertificate[],
  rootDescriptor: PrincipalDescriptor | undefined,
  resource: ResourceId,
): ChainRefusal | { readonly valid: true; readonly inScope: boolean } {
  if (issuers.length >= MAX_CHAIN_LENGTH)
    return refuse("structure", `a chain holds at most ${MAX_CHAIN_LENGTH} certificates (c1)`);
  const payloads = [leaf, ...issuers.map((c) => c.payload)];
  try {
    checkDeviceCertificatePayload(leaf);
    checkChainStructure(payloads, leaf.root);
  } catch (e) {
    if (e instanceof LfcpError && e.code === "INVALID_STRUCTURE")
      return refuse("structure", e.message);
    throw e;
  }
  if (rootDescriptor === undefined)
    return refuse("root-descriptor", "the root's descriptor is not known (step 2)");
  const signatures =
    rootDescriptorMismatch(leaf.root, rootDescriptor) ?? verifySignatures(issuers, rootDescriptor);
  if (signatures !== undefined) return signatures;
  const authority = checkAuthority(payloads, resource);
  return typeof authority === "boolean" ? { valid: true, inScope: authority } : authority;
}
