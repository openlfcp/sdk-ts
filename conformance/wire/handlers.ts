// LFCP-TEST-VECTORS-01 handlers for sdk-ts (LFCP-017; extended by each later task).
//
// One handler per "<type>/<kind>". A handler checks what the SDK implements
// today and names, as pending parts, what later tasks implement (the owner
// of each part is in pending.json). Values come only from the loaded suite.

import { createDataUnit, createSnapshot } from "@openlfcp/client";
import {
  bytesEqual,
  dataEpoch,
  fromBase64url,
  fromHex,
  LfcpError,
  type PrincipalId,
  resourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import {
  dataUnitNonce,
  decryptDataUnit,
  decryptSnapshot,
  dekCommitment,
  deriveActorDataKey,
  deriveSnapshotKey,
  encryptDataUnit,
  encryptSnapshot,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  type ResourceDEK,
  snapshotNonce,
  verifyEd25519,
} from "@openlfcp/crypto";
import {
  type AnyMessage,
  type AuthTranscriptFields,
  authTranscript,
  type ControlPutBody,
  type ControlRecord,
  canonicalFrontierFromCbor,
  checkSnapshot,
  clientReceive,
  type DataProfileCodec,
  dataUnitAad,
  decodeControlRecord,
  decodeControlRecordPayload,
  decodeDataUnitPayload,
  decodeEnvelope,
  decodeKeyPackagePayload,
  decodeMessage,
  decodePrincipalDescriptor,
  decodeSnapshotPayload,
  derivePrincipalId,
  ERROR_CODE,
  encodeControlRecordPayload,
  encodeMessage,
  encodePrincipalDescriptor,
  expectedSignerOf,
  InMemorySeenUnits,
  type KeyPackagePayload,
  type KeyPackageRecipient,
  keyPackageHpkeAad,
  keyPackageHpkeInfo,
  type LfcpMessage,
  liveHavesOf,
  MESSAGE_TYPE,
  messageErrorWireCode,
  normalizeLiveHaves,
  objectId,
  openKeyPackage,
  type Parsed,
  parseControlRecord,
  parseDataUnit,
  parseKeyPackage,
  parseOwnerTransferAccept,
  parseOwnerTransferOffer,
  parseSignedObject,
  parseSnapshot,
  principalDescriptorFromKeys,
  proposeControlPut,
  type ReceivedDataUnit,
  receiveDataUnit,
  receiveSnapshot,
  type Signer,
  serverReceive,
  signControlRecord,
  signObject,
  sigStructureBytes,
  snapshotAad,
  startClientHandshake,
  startServerSession,
  validateControlChain,
  verifyAuthProof,
  verifyGenesis,
  verifyKeyPackage,
  verifySignedObject,
  WIRE_PROFILE,
} from "@openlfcp/wire";
import {
  type CborValue,
  decodeStrict,
  encode,
  isCborMap,
  isDeterministic,
} from "@openlfcp/wire/cbor";
import {
  AEAD_ChaCha20Poly1305,
  KDF_HKDF_SHA256,
  KEM_DHKEM_X25519_HKDF_SHA256,
} from "@panva/hpke-noble";
import { CipherSuite, type KEMFactory } from "hpke";
import { bytesCheck, check, describeError, equalCheck, outcomeCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, VectorCase, VectorSuite } from "../runner.js";
import { SIGNATURE_FAILURE, wireCodeOf } from "./error-map.js";

type Fields = Readonly<Record<string, unknown>> | undefined;

/** The bytes of a `{hex}` value; throws (failing the case) when absent. */
function hexOf(fields: Fields, name: string): Uint8Array {
  const v = fields?.[name] as { hex?: unknown } | undefined;
  if (typeof v?.hex !== "string") throw new Error(`field ${name} is not a {hex} value`);
  return fromHex(v.hex);
}

function b64Of(fields: Fields, name: string): string {
  const v = fields?.[name] as { b64url?: unknown } | undefined;
  if (typeof v?.b64url !== "string") throw new Error(`field ${name} is not a {b64url} value`);
  return v.b64url;
}

const has = (fields: Fields, name: string): boolean => fields?.[name] !== undefined;

// ---------------------------------------------------------------------------
// Fixture Principals, from the suite's principal cases (checked by `principal`).

const PRINCIPALS = new WeakMap<VectorSuite, Map<string, Signer>>();

/** Fixture signers by Principal ID hex and by name ("OWNER" for principal_owner). */
function principals(context: HandlerContext): Map<string, Signer> {
  let map = PRINCIPALS.get(context.suite);
  if (map === undefined) {
    map = new Map();
    for (const c of context.suite.cases) {
      if (c.type !== "bytes" || c.kind !== "principal") continue;
      const key = importSigningKey(hexOf(c.inputs, "ed25519_seed"));
      const signer: Signer = {
        key,
        descriptor: principalDescriptorFromKeys(
          key,
          importAgreementKey(hexOf(c.inputs, "x25519_private")),
        ),
      };
      map.set(toHex(signer.descriptor.principalId), signer);
      map.set(c.id.replace(/^principal_/, "").toUpperCase(), signer);
    }
    PRINCIPALS.set(context.suite, map);
  }
  return map;
}

function signerFor(context: HandlerContext, id: PrincipalId): Signer {
  const s = principals(context).get(toHex(id));
  if (s === undefined) throw new Error(`no fixture Principal ${toHex(id)} in the suite`);
  return s;
}

// ---------------------------------------------------------------------------
// Check groups.

/** The bytes decode strictly and re-encode to themselves (§5.2). */
function deterministic(name: string, bytes: Uint8Array): Check {
  try {
    return bytesCheck(name, bytes, encode(decodeStrict(bytes)));
  } catch (e) {
    return { name, ok: false, message: `does not decode as strict CBOR: ${describeError(e)}` };
  }
}

/** The expected value equals one decoded from somewhere else. */
function sameBytes(name: string, expected: Uint8Array, actual: () => Uint8Array): Check {
  try {
    return bytesCheck(name, expected, actual());
  } catch (e) {
    return { name, ok: false, message: `threw ${describeError(e)}` };
  }
}

/**
 * A received signed object: parse with `parse`, verify against the signer
 * named by `signerOf(parsed)`, re-sign `payload` (Ed25519 is deterministic)
 * and check the exact payload bytes.
 */
function signedObject<P>(
  field: string,
  context: HandlerContext,
  cose: Uint8Array,
  parse: (bytes: Uint8Array) => Parsed<P>,
  signerOf: (parsed: Parsed<P>) => PrincipalId,
  payload?: Uint8Array,
): { checks: Check[]; parsed?: Parsed<P> } {
  let parsed: Parsed<P>;
  try {
    parsed = parse(cose);
  } catch (e) {
    return { checks: [{ name: `${field}/parse`, ok: false, message: describeError(e) }] };
  }
  const checks: Check[] = [{ name: `${field}/parse`, ok: true }];
  checks.push(
    check(`${field}/verify`, () => {
      const v = verifySignedObject(parsed.signed, signerFor(context, signerOf(parsed)).descriptor);
      return v.valid || `verification failed: ${v.reason}`;
    }),
  );
  if (payload !== undefined) {
    checks.push(bytesCheck(`${field}/payload`, payload, parsed.signed.payloadBytes));
    checks.push(
      sameBytes(
        `${field}/sign`,
        cose,
        () => signObject(payload, signerFor(context, signerOf(parsed))).bytes,
      ),
    );
  }
  return { checks, parsed };
}

const kidOf = (p: Parsed<unknown>): PrincipalId => p.signed.kid;

// ---------------------------------------------------------------------------
// bytes cases

const principal: Handler = (c) => {
  const key = importSigningKey(hexOf(c.inputs, "ed25519_seed"));
  const agreement = importAgreementKey(hexOf(c.inputs, "x25519_private"));
  const descriptorCbor = hexOf(c.expected, "descriptor_cbor");
  return {
    checks: [
      bytesCheck("ed25519_public", hexOf(c.expected, "ed25519_public"), key.publicKey),
      bytesCheck("x25519_public", hexOf(c.expected, "x25519_public"), agreement.publicKey),
      sameBytes("principal_id", hexOf(c.expected, "principal_id"), () =>
        derivePrincipalId(key.publicKey, agreement.publicKey),
      ),
      sameBytes("descriptor_cbor", descriptorCbor, () =>
        encodePrincipalDescriptor(principalDescriptorFromKeys(key, agreement)),
      ),
      deterministic("descriptor_cbor/deterministic", descriptorCbor),
      sameBytes(
        "descriptor_cbor/decode",
        hexOf(c.expected, "principal_id"),
        () => decodePrincipalDescriptor(descriptorCbor).principalId,
      ),
    ],
  };
};

const controlRecord: Handler = (c, context) => {
  const e = c.expected;
  const payload = hexOf(e, "payload_cbor");
  const cose = hexOf(e, "cose_sign1");
  const protectedHeader = hexOf(e, "protected_header_cbor");
  const signer = principals(context).get(String(c.inputs?.signer));
  const signed = signedObject(
    "cose_sign1",
    context,
    cose,
    parseControlRecord,
    (p) => p.payload.issuer,
    payload,
  );
  return {
    checks: [
      deterministic("payload_cbor/deterministic", payload),
      check("payload_cbor/decode", () => {
        const p = decodeControlRecordPayload(payload);
        if (signer === undefined)
          return `inputs.signer ${String(c.inputs?.signer)} is not a fixture Principal`;
        return bytesEqual(p.issuer, signer.descriptor.principalId) || "issuer is not inputs.signer";
      }),
      deterministic("protected_header_cbor/deterministic", protectedHeader),
      sameBytes(
        "protected_header_cbor",
        protectedHeader,
        () => parseSignedObject(cose).protectedBytes,
      ),
      deterministic("sig_structure_cbor/deterministic", hexOf(e, "sig_structure_cbor")),
      bytesCheck(
        "sig_structure_cbor",
        hexOf(e, "sig_structure_cbor"),
        sigStructureBytes(protectedHeader, payload),
      ),
      ...signed.checks,
      bytesCheck("record_id", hexOf(e, "record_id"), objectId(cose)),
      ...(signed.parsed
        ? [bytesCheck("record_id/parsed", hexOf(e, "record_id"), signed.parsed.signed.id)]
        : []),
      ...typedControlChecks(c, context, cose, payload, hexOf(e, "record_id")),
      chainCheck(c, context, cose),
    ],
  };
};

// ---------------------------------------------------------------------------
// LFCP-020: Control Chain validation over the suite's published records.

const PUBLISHED_CHAIN = new WeakMap<VectorSuite, Uint8Array[]>();

/** The exact COSE bytes of every bytes/control_record case of the suite. */
function publishedChain(context: HandlerContext): Uint8Array[] {
  let chain = PUBLISHED_CHAIN.get(context.suite);
  if (chain === undefined) {
    chain = context.suite.cases
      .filter((x) => x.type === "bytes" && x.kind === "control_record")
      .map((x) => hexOf(x.expected, "cose_sign1"));
    PUBLISHED_CHAIN.set(context.suite, chain);
  }
  return chain;
}

/** The published records form one linear chain; this one is at its seq, and the last is the head. */
function chainCheck(c: VectorCase, context: HandlerContext, cose: Uint8Array): Check {
  return check("cose_sign1/chain", () => {
    const result = validateControlChain(publishedChain(context));
    if (result.kind !== "linear")
      return `the published records do not form a linear chain: ${result.kind}`;
    const id = toHex(objectId(cose));
    const position = result.records.findIndex((r) => toHex(r.signed.id) === id);
    if (position < 0) return `${c.id} is not on the validated chain`;
    if (BigInt(position) !== decodeControlRecord(cose).payload.controlSeq)
      return `${c.id} is at chain position ${position}, not at its control_seq`;
    if (position === result.records.length - 1 && toHex(result.state.head) !== id)
      return "the last record is not the Control Head";
    return true;
  });
}

/** The value a `{case, field}` reference in a vector's context names. */
function referenced(context: HandlerContext, ref: unknown): Uint8Array {
  const r = ref as { case?: string; field?: string; in?: string } | undefined;
  const target = r?.case === undefined ? undefined : context.caseById(r.case);
  if (target === undefined || r?.field === undefined)
    throw new Error(`bad reference ${JSON.stringify(ref)}`);
  return hexOf(r.in === "inputs" ? target.inputs : target.expected, r.field);
}

/**
 * A received Control Record against the published chain: CONTROL_CONFLICT
 * for a fork, the chain's wire code when invalid, null when it extends the
 * chain. The diagnostics are checked against the vector's context.
 *
 * The receiver knows the descriptor of the Principal the vector names in
 * inputs.signer (G-RS3), as it would from the sender's session, so a
 * record whose issuer no earlier record describes (extension_type_non_owner_C1:
 * BOB at C0) reaches its authority rule instead of stopping at
 * MISSING_DEPENDENCY (§13.1).
 */
const controlRecordNegative: Handler = (c, context) => {
  const cose = hexOf(c.inputs, "cose_sign1");
  const named = principals(context).get(String(c.inputs?.signer))?.descriptor;
  const result = validateControlChain([...publishedChain(context), cose], {
    resolvePrincipal: (id) =>
      named !== undefined && bytesEqual(id, named.principalId) ? named : undefined,
  });
  const checks: Check[] = [];
  if (has(c.inputs, "record_id"))
    checks.push(bytesCheck("inputs.record_id", hexOf(c.inputs, "record_id"), objectId(cose)));
  const ctx = c.context as { previous_record?: unknown; competing_record?: unknown } | undefined;
  if (result.kind === "conflict" && ctx?.previous_record !== undefined) {
    checks.push(
      check(
        "context.previous_record",
        () =>
          bytesEqual(
            result.commonHead ?? new Uint8Array(0),
            referenced(context, ctx.previous_record),
          ) || "the common head is not the context's previous record",
      ),
    );
  }
  if (result.kind === "conflict" && ctx?.competing_record !== undefined) {
    checks.push(
      check("context.competing_record", () => {
        const ids = result.competing.map(toHex);
        return (
          (ids.includes(toHex(referenced(context, ctx.competing_record))) &&
            ids.includes(toHex(objectId(cose)))) ||
          "the competing records are not the context's record and the input"
        );
      }),
    );
  }
  const actual =
    result.kind === "conflict"
      ? result.wireCode
      : result.kind === "invalid"
        ? result.wireCode
        : null;
  const outcome = negative(c, actual);
  return { checks: [...checks, ...outcome.checks], pending: outcome.pending };
};

/**
 * LFCP-022, LFCP-026: a CONTROL_PUT against the coordinator's state at the
 * vector's current head. The message is decoded with the message codec; a
 * body that does not decode (a null expected head, §47) fails before any
 * state is needed.
 */
const controlPutNegative: Handler = (c, context) => {
  const checks: Check[] = [
    check(
      "inputs.message_cbor/type",
      () => decodeEnvelope(hexOf(c.inputs, "message_cbor")).code === MESSAGE_TYPE.CONTROL_PUT,
    ),
  ];
  let body: ControlPutBody;
  try {
    const message = decodeMessage(hexOf(c.inputs, "message_cbor"));
    if (message.type !== "CONTROL_PUT") throw new Error(`a ${message.type}, not a CONTROL_PUT`);
    body = message.body;
  } catch (e) {
    const outcome = negative(c, messageErrorWireCode(e));
    return { checks: [...checks, ...outcome.checks], pending: outcome.pending };
  }
  const ctx = c.context as { current_control_head?: unknown } | undefined;
  const chain = validateControlChain(publishedChain(context));
  if (chain.kind !== "linear") throw new Error("the published Control Chain does not validate");
  const head = referenced(context, ctx?.current_control_head);
  const state = chain.stateAt(head);
  if (state === undefined) throw new Error("the context head is not on the published chain");
  const result = proposeControlPut(state, body);
  if (result.kind === "head-mismatch")
    checks.push(bytesCheck("context.current_control_head", head, result.currentHead));
  const actual =
    result.kind === "accepted" || result.kind === "already-committed" ? null : result.wireCode;
  const outcome = negative(c, actual);
  return { checks: [...checks, ...outcome.checks], pending: outcome.pending };
};

/**
 * LFCP-019: the typed body decodes, re-encodes to the exact payload and
 * re-signs (as the issuer) to the exact object and record ID; a Genesis
 * verifies against the owner in its body; an ownership transfer commit
 * carries the exact offer and accept objects of the owner_transfer case.
 */
function typedControlChecks(
  c: VectorCase,
  context: HandlerContext,
  cose: Uint8Array,
  payload: Uint8Array,
  recordId: Uint8Array,
): Check[] {
  let record: ControlRecord;
  try {
    record = decodeControlRecord(cose);
  } catch (e) {
    return [{ name: "payload_cbor/typed-body", ok: false, message: describeError(e) }];
  }
  const header = {
    resourceId: record.payload.resourceId,
    controlSeq: record.payload.controlSeq,
    prevControlId: record.payload.prevControlId,
  };
  const resign = () =>
    signControlRecord(header, record.body, signerFor(context, record.payload.issuer));
  const checks: Check[] = [
    sameBytes("payload_cbor/typed-body", payload, () =>
      encodeControlRecordPayload(header, record.payload.issuer, record.body),
    ),
    sameBytes("cose_sign1/sign-typed", cose, () => resign().bytes),
    sameBytes("record_id/sign-typed", recordId, () => resign().recordId),
  ];
  if (record.body.type === "GENESIS") {
    checks.push(
      check("cose_sign1/genesis-owner", () => {
        const v = verifyGenesis(record);
        return v.valid || `Genesis does not verify against its owner: ${v.reason}`;
      }),
    );
  }
  const body = record.body;
  if (body.type === "OWNER_TRANSFER_COMMIT") {
    const transfer = context.suite.cases.find(
      (x) => x.type === "bytes" && x.kind === "owner_transfer",
    );
    checks.push(
      check("payload_cbor/transfer-objects", () => {
        if (transfer === undefined) return "the suite has no owner_transfer case";
        return (
          (bytesEqual(body.offer, hexOf(transfer.expected, "offer_cose_sign1")) &&
            bytesEqual(body.accept, hexOf(transfer.expected, "accept_cose_sign1"))) ||
          `${c.id} does not carry the owner_transfer offer and accept`
        );
      }),
    );
  }
  return checks;
}

const ownerTransfer: Handler = (c, context) => {
  const checks: Check[] = [];
  for (const side of ["offer", "accept"]) {
    const payload = hexOf(c.expected, `${side}_payload_cbor`);
    const cose = hexOf(c.expected, `${side}_cose_sign1`);
    checks.push(deterministic(`${side}_payload_cbor/deterministic`, payload));
    checks.push(
      ...signedObject(
        `${side}_cose_sign1`,
        context,
        cose,
        (b) => ({ signed: parseSignedObject(b), payload: null }),
        kidOf,
        payload,
      ).checks,
    );
    checks.push(bytesCheck(`${side}_id`, hexOf(c.expected, `${side}_id`), objectId(cose)));
  }
  // LFCP-019: typed payloads (§23.1, §23.2; deferred from MVP 0.1, structure only).
  checks.push(
    check("offer_payload_cbor/typed", () => {
      const offer = parseOwnerTransferOffer(hexOf(c.expected, "offer_cose_sign1")).payload;
      return (
        bytesEqual(offer.nonce, hexOf(c.inputs, "nonce")) || "the offer nonce is not inputs.nonce"
      );
    }),
    check("accept_payload_cbor/typed", () => {
      const offer = parseOwnerTransferOffer(hexOf(c.expected, "offer_cose_sign1")).payload;
      const accept = parseOwnerTransferAccept(hexOf(c.expected, "accept_cose_sign1"));
      if (!bytesEqual(accept.payload.offerId, hexOf(c.expected, "offer_id")))
        return "the accept does not name the offer ID";
      if (!bytesEqual(accept.payload.newOwner, offer.proposedOwner.principalId))
        return "the accept is not by the proposed owner";
      return (
        bytesEqual(accept.signed.kid, accept.payload.newOwner) ||
        "the accept is not signed by the new owner"
      );
    }),
  );
  return { checks };
};

/** The X25519 key pair and descriptor of a fixture Principal, from its principal case. */
function recipientKeys(context: HandlerContext, id: Uint8Array): KeyPackageRecipient {
  for (const c of context.suite.cases) {
    if (c.type !== "bytes" || c.kind !== "principal") continue;
    if (!bytesEqual(hexOf(c.expected, "principal_id"), id)) continue;
    const signer = principals(context).get(toHex(id));
    if (signer === undefined) break;
    return {
      descriptor: signer.descriptor,
      agreement: importAgreementKey(hexOf(c.inputs, "x25519_private")),
    };
  }
  throw new Error(`no fixture Principal ${toHex(id)}`);
}

/**
 * TEST ONLY: the library's X25519 KEM with its ephemeral key derived from
 * the published ikmE (RFC 9180 §7.1.3 DeriveKeyPair, G-KP2), so a seal is
 * reproducible. Only GenerateKeyPair is replaced; Encap, the key schedule
 * and the AEAD stay the library's. The SDK never does this: sealDek always
 * draws a fresh ephemeral key.
 */
const ikmEKem =
  (ikmE: Uint8Array): KEMFactory =>
  () => {
    const kem = KEM_DHKEM_X25519_HKDF_SHA256();
    return { ...kem, GenerateKeyPair: (extractable) => kem.DeriveKeyPair(ikmE, extractable) };
  };

/** A Base-mode seal of `plaintext` to `recipientPublicKey` with skE = DeriveKeyPair(ikmE). */
async function sealWithIkmE(
  ikmE: Uint8Array,
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
) {
  const kemFactory = ikmEKem(ikmE);
  const suite = new CipherSuite(kemFactory, KDF_HKDF_SHA256, AEAD_ChaCha20Poly1305);
  const pkR = await suite.DeserializePublicKey(recipientPublicKey);
  const ephemeral = await suite.DeriveKeyPair(ikmE, true);
  const { shared_secret } = await kemFactory().Encap(pkR);
  const sealed = await suite.Seal(pkR, plaintext, { info, aad });
  return {
    skE: await suite.SerializePrivateKey(ephemeral.privateKey),
    enc: sealed.encapsulatedSecret,
    sharedSecret: shared_secret,
    ciphertext: sealed.ciphertext,
  };
}

/** The recipient side of the KEM: the shared secret from enc and the recipient's X25519 secret. */
async function decapShared(enc: Uint8Array, recipientSecret: Uint8Array): Promise<Uint8Array> {
  const kem = KEM_DHKEM_X25519_HKDF_SHA256();
  const skR = await kem.DeserializePrivateKey(recipientSecret, false);
  return kem.Decap(enc, skR, undefined);
}

/**
 * LFCP-024, G-KP2. Every HPKE field is checked: info and AAD built from
 * the payload (§25.1); skE = DeriveKeyPair(inputs.hpke_ephemeral_ikm) and
 * enc = its public key; the shared secret from both the sender (Encap) and
 * the recipient (Decap) side; enc and ciphertext reproduced through the
 * library seal; the published key and base_nonce produce the ciphertext
 * through the suite AEAD; the package opens for its recipient to the epoch
 * DEK with the chain's commitment; and the package is authorized at its
 * head (§25.2).
 */
const keyPackage: Handler = async (c, context) => {
  const e = c.expected;
  const payload = hexOf(e, "payload_cbor");
  const cose = hexOf(e, "cose_sign1");
  const signed = signedObject(
    "cose_sign1",
    context,
    cose,
    parseKeyPackage,
    (p) => expectedSignerOf(p.payload),
    payload,
  );
  const p = decodeKeyPackagePayload(payload);
  const info = keyPackageHpkeInfo(p.resourceId, p.dataEpoch, p.recipient);
  const aad = keyPackageHpkeAad(p.resourceId, p.dataEpoch, p.controlHead);
  const ikmE = hexOf(c.inputs, "hpke_ephemeral_ikm");
  const recipient = recipientKeys(context, p.recipient);
  const dek = dekForEpoch(context, p.dataEpoch);
  const dekBytes = exportSecretKeyBytes(dek);
  const seal = await sealWithIkmE(ikmE, recipient.descriptor.x25519PublicKey, dekBytes, info, aad);
  const decapped = await decapShared(
    hexOf(e, "hpke_enc"),
    exportSecretKeyBytes(recipient.agreement),
  );
  const published = await AEAD_ChaCha20Poly1305().Seal(
    hexOf(e, "hpke_key"),
    hexOf(e, "hpke_base_nonce"),
    aad,
    dekBytes,
  );
  const chain = validateControlChain(publishedChain(context));
  const checks: Check[] = [
    deterministic("hpke_info_cbor/deterministic", hexOf(e, "hpke_info_cbor")),
    bytesCheck("hpke_info_cbor/construct", hexOf(e, "hpke_info_cbor"), info),
    deterministic("hpke_aad_cbor/deterministic", hexOf(e, "hpke_aad_cbor")),
    bytesCheck("hpke_aad_cbor/construct", hexOf(e, "hpke_aad_cbor"), aad),
    bytesCheck("hpke_ephemeral_private/derive", hexOf(e, "hpke_ephemeral_private"), seal.skE),
    sameBytes("hpke_enc/payload-field", hexOf(e, "hpke_enc"), () => p.hpkeEnc),
    bytesCheck(
      "hpke_enc/derive",
      hexOf(e, "hpke_enc"),
      importAgreementKey(hexOf(e, "hpke_ephemeral_private")).publicKey,
    ),
    bytesCheck("hpke_enc/seal", hexOf(e, "hpke_enc"), seal.enc),
    bytesCheck("hpke_shared_secret/encap", hexOf(e, "hpke_shared_secret"), seal.sharedSecret),
    bytesCheck("hpke_shared_secret/decap", hexOf(e, "hpke_shared_secret"), decapped),
    bytesCheck("hpke_key/aead", hexOf(e, "hpke_ciphertext"), published),
    bytesCheck("hpke_base_nonce/aead", hexOf(e, "hpke_ciphertext"), published),
    sameBytes("hpke_ciphertext/payload-field", hexOf(e, "hpke_ciphertext"), () => p.hpkeCiphertext),
    bytesCheck("hpke_ciphertext/seal", hexOf(e, "hpke_ciphertext"), seal.ciphertext),
    deterministic("payload_cbor/deterministic", payload),
    check("payload_cbor/decode", () => p.kind === "key-package"),
    ...signed.checks,
    bytesCheck("package_id", hexOf(e, "package_id"), objectId(cose)),
  ];
  if (chain.kind === "linear") {
    const parsed = parseKeyPackage(cose);
    checks.push(
      check("cose_sign1/authorized", () => {
        const v = verifyKeyPackage(chain, parsed);
        return v.kind === "authorized" || `${v.reason}: ${v.message}`;
      }),
    );
    const commitment = chain.state.epochs.get(String(p.dataEpoch))?.dekCommitment;
    let opened: Uint8Array | string;
    try {
      opened =
        commitment === undefined
          ? "the epoch has no commitment on the chain"
          : exportSecretKeyBytes(await openKeyPackage(parsed, recipient, commitment));
    } catch (err) {
      opened = describeError(err);
    }
    checks.push(
      typeof opened === "string"
        ? { name: "hpke_ciphertext/open", ok: false, message: opened }
        : bytesCheck("hpke_ciphertext/open", dekBytes, opened),
    );
  }
  return { checks };
};

// ---------------------------------------------------------------------------
// Data Epoch keys. The suite's dek_commitments case maps each
// fixtures.resource.dek<N> to its epoch through inputs.dek<N>_epoch.

function resourceFixture(context: HandlerContext): Fields {
  return (context.suite.fixtures as { resource?: Fields } | undefined)?.resource;
}

/** The fixture DEK for `epoch`, found through the dek_commitment case's inputs. */
function dekForEpoch(context: HandlerContext, epoch: bigint): ResourceDEK {
  for (const c of context.suite.cases) {
    if (c.type !== "bytes" || c.kind !== "dek_commitment") continue;
    for (const [field, value] of Object.entries(c.inputs ?? {})) {
      const m = /^(dek\d+)_epoch$/.exec(field);
      if (m && BigInt(value as number) === epoch)
        return importResourceDEK(hexOf(resourceFixture(context), m[1] as string));
    }
  }
  throw new Error(`no fixture DEK for epoch ${epoch}`);
}

const dekCommitments: Handler = (c, context) => {
  const resource = hexOf(resourceFixture(context), "id");
  const checks: Check[] = [];
  for (const [field, value] of Object.entries(c.inputs ?? {})) {
    const m = /^(dek\d+)_epoch$/.exec(field);
    if (m === null) continue;
    const name = `${m[1]}_commitment`;
    checks.push(
      sameBytes(name, hexOf(c.expected, name), () =>
        dekCommitment(
          resourceId(resource),
          dataEpoch(BigInt(value as number)),
          importResourceDEK(hexOf(resourceFixture(context), m[1] as string)),
        ),
      ),
    );
  }
  return { checks };
};

/** The validated published chain, as a view; throws when it does not validate. */
function publishedView(context: HandlerContext) {
  const chain = validateControlChain(publishedChain(context));
  if (chain.kind !== "linear") throw new Error("the published Control Chain does not validate");
  return chain;
}

/** The opaque profile the vectors use: the plaintext bytes themselves, under the chain's data_profile. */
const opaqueProfile = (dataProfile: string): DataProfileCodec<Uint8Array> => ({
  dataProfile,
  encode: (value) => Uint8Array.from(value),
  decode: (plaintext) => Uint8Array.from(plaintext),
});

/** A receiver for the published chain; DEKs come from the fixtures by epoch. */
function dataReceiver(context: HandlerContext) {
  const view = publishedView(context);
  const seen = new InMemorySeenUnits();
  return {
    view,
    receive: (bytes: Uint8Array) =>
      receiveDataUnit(view, bytes, {
        seen,
        dek: (epoch) => dekForEpoch(context, epoch),
        profile: opaqueProfile(view.state.dataProfile),
      }),
  };
}

/**
 * LFCP-025. Every published field is checked: the actor key and nonce
 * (§12), the AAD built from the payload (§26.1), the ciphertext encrypted
 * from inputs.plaintext_hex and decrypted back, and the whole unit
 * re-created through createDataUnit from the vector inputs (the sequence
 * from a reservation fixed to the payload's, the previous unit, head,
 * actor and DEK) to the exact cose_sign1 and unit_id. The published unit
 * must then be cryptographically valid on the published chain.
 */
const dataUnit: Handler = async (c, context) => {
  const e = c.expected;
  const payload = hexOf(e, "payload_cbor");
  const cose = hexOf(e, "cose_sign1");
  const plaintext = hexOf(c.inputs, "plaintext_hex");
  const signed = signedObject(
    "cose_sign1",
    context,
    cose,
    parseDataUnit,
    (p) => expectedSignerOf(p.payload),
    payload,
  );
  const p = decodeDataUnitPayload(payload);
  const dek = dekForEpoch(context, p.dataEpoch);
  const actorKey = deriveActorDataKey(dek, p.resourceId, p.dataEpoch, p.actor);
  const actor = principals(context).get(String(c.inputs?.signer));
  const checks: Check[] = [
    check("inputs.dek", () => {
      const named = hexOf(resourceFixture(context), String(c.inputs?.dek));
      return bytesEqual(named, exportSecretKeyBytes(dek)) || "inputs.dek is not the epoch's DEK";
    }),
    sameBytes("actor_key/derive", hexOf(e, "actor_key"), () => exportSecretKeyBytes(actorKey)),
    sameBytes("nonce/derive", hexOf(e, "nonce"), () => dataUnitNonce(p.actorSeq)),
    deterministic("aad_cbor/deterministic", hexOf(e, "aad_cbor")),
    sameBytes("aad_cbor/construct", hexOf(e, "aad_cbor"), () => dataUnitAad(p)),
    sameBytes("ciphertext/payload-field", hexOf(e, "ciphertext"), () => p.ciphertext),
    sameBytes("ciphertext/encrypt", hexOf(e, "ciphertext"), () =>
      encryptDataUnit(actorKey, p.actorSeq, hexOf(e, "aad_cbor"), plaintext),
    ),
    sameBytes("ciphertext/decrypt", plaintext, () =>
      decryptDataUnit(actorKey, p.actorSeq, dataUnitAad(p), p.ciphertext),
    ),
    deterministic("payload_cbor/deterministic", payload),
    check("payload_cbor/decode", () => p.kind === "data-unit"),
    ...signed.checks,
    bytesCheck("unit_id", hexOf(e, "unit_id"), objectId(cose)),
  ];
  let created: Awaited<ReturnType<typeof createDataUnit>> | string;
  try {
    if (actor === undefined)
      throw new Error(`inputs.signer ${String(c.inputs?.signer)} is unknown`);
    const view = publishedView(context);
    created = await createDataUnit({
      view,
      controlHead: p.controlHead,
      actor,
      dek,
      sequences: { reserveNext: () => Promise.resolve(p.actorSeq) },
      previousUnitId: p.prevDataUnitId,
      profile: opaqueProfile(view.state.dataProfile),
      value: plaintext,
    });
  } catch (err) {
    created = describeError(err);
  }
  if (typeof created === "string")
    checks.push({ name: "cose_sign1/create", ok: false, message: created });
  else
    checks.push(
      bytesCheck("cose_sign1/create", cose, created.bytes),
      bytesCheck("unit_id/create", hexOf(e, "unit_id"), created.unitId),
    );
  // Receive the published units in order up to this one, so its actor
  // chain links (§26.2): D2 needs D1.
  const receiver = dataReceiver(context);
  let received: ReceivedDataUnit<unknown> | undefined;
  for (const u of context.suite.cases) {
    if (u.type !== "bytes" || u.kind !== "data_unit") continue;
    const r = await receiver.receive(hexOf(u.expected, "cose_sign1"));
    if (u.id === c.id) {
      received = r;
      break;
    }
  }
  if (received === undefined) throw new Error(`${c.id} is not a published Data Unit`);
  checks.push(
    check(
      "cose_sign1/receive",
      () =>
        received.kind === "accepted" ||
        received.kind === "quarantined" ||
        `the published unit is ${received.kind}`,
    ),
  );
  return { checks };
};

/**
 * LFCP-029. Besides the payload, frontier, key, nonce, COSE and ID checks:
 * the AAD rebuilt from the payload (§29.1.3), the ciphertext encrypted
 * from inputs.plaintext_hex and decrypted back (§29.1.4), and the whole
 * Snapshot re-created by createSnapshot from the vector inputs (a
 * reservation fixed to inputs.snapshot_sequence, the published frontier)
 * to the exact cose_sign1 and snapshot_id; then receiveSnapshot accepts
 * the published bytes on the published chain.
 */
const snapshot: Handler = async (c, context) => {
  const e = c.expected;
  const payload = hexOf(e, "payload_cbor");
  const cose = hexOf(e, "cose_sign1");
  const frontier = hexOf(e, "frontier_cbor");
  const protectedHeader = hexOf(e, "protected_header_cbor");
  const signed = signedObject(
    "cose_sign1",
    context,
    cose,
    parseSnapshot,
    (p) => expectedSignerOf(p.payload),
    payload,
  );
  const field5 = (): Uint8Array => {
    const map = decodeStrict(payload);
    const entry = isCborMap(map) ? map.entries.find(([k]) => k === 5) : undefined;
    if (entry === undefined) throw new Error("payload has no field 5");
    return encode(entry[1] as CborValue);
  };
  const p = decodeSnapshotPayload(payload);
  const plaintext = hexOf(c.inputs, "plaintext_hex");
  const dek = dekForEpoch(context, p.dataEpoch);
  const key = deriveSnapshotKey(dek, p.resourceId, p.dataEpoch, p.publisher);
  const view = publishedView(context);
  const profile = opaqueProfile(view.state.dataProfile);
  let created: Awaited<ReturnType<typeof createSnapshot>> | string;
  try {
    const publisher = principals(context).get(String(c.inputs?.signer));
    if (publisher === undefined)
      throw new Error(`inputs.signer ${String(c.inputs?.signer)} is unknown`);
    created = await createSnapshot({
      view,
      controlHead: hexOf(c.inputs, "control_head"),
      publisher,
      dek,
      sequences: {
        reserveNext: () => Promise.resolve(BigInt(Number(c.inputs?.snapshot_sequence))),
      },
      frontier: liveHavesOf(canonicalFrontierFromCbor(decodeStrict(frontier))),
      profile,
      value: plaintext,
    });
  } catch (err) {
    created = describeError(err);
  }
  const received = await receiveSnapshot(view, cose, {
    dek: (e) => dekForEpoch(context, e),
    profile,
  });
  return {
    checks: [
      check("inputs.dek", () => {
        const named = hexOf(resourceFixture(context), String(c.inputs?.dek));
        return bytesEqual(named, exportSecretKeyBytes(dek)) || "inputs.dek is not the epoch's DEK";
      }),
      sameBytes("aad_cbor/construct", hexOf(e, "aad_cbor"), () => snapshotAad(p)),
      sameBytes("ciphertext/encrypt", hexOf(e, "ciphertext"), () =>
        encryptSnapshot(key, p.snapshotSeq, hexOf(e, "aad_cbor"), plaintext),
      ),
      sameBytes("ciphertext/decrypt", plaintext, () =>
        decryptSnapshot(key, p.snapshotSeq, snapshotAad(p), p.ciphertext),
      ),
      typeof created === "string"
        ? { name: "cose_sign1/create", ok: false, message: created }
        : bytesCheck("cose_sign1/create", cose, created.bytes),
      ...(typeof created === "string"
        ? []
        : [bytesCheck("snapshot_id/create", hexOf(e, "snapshot_id"), created.snapshotId)]),
      check(
        "cose_sign1/receive",
        () =>
          (received.kind === "accepted" && bytesEqual(received.value as Uint8Array, plaintext)) ||
          `the published Snapshot is ${received.kind}`,
      ),
      deterministic("frontier_cbor/deterministic", frontier),
      check("frontier_cbor/canonical", () =>
        Array.isArray(canonicalFrontierFromCbor(decodeStrict(frontier))),
      ),
      sameBytes("frontier_cbor/payload-field", frontier, field5),
      sameBytes("snapshot_key/derive", hexOf(e, "snapshot_key"), () => {
        const p = decodeSnapshotPayload(payload);
        const dek = dekForEpoch(context, p.dataEpoch);
        return exportSecretKeyBytes(deriveSnapshotKey(dek, p.resourceId, p.dataEpoch, p.publisher));
      }),
      sameBytes("nonce/derive", hexOf(e, "nonce"), () =>
        snapshotNonce(decodeSnapshotPayload(payload).snapshotSeq),
      ),
      deterministic("aad_cbor/deterministic", hexOf(e, "aad_cbor")),
      sameBytes(
        "ciphertext/payload-field",
        hexOf(e, "ciphertext"),
        () => decodeSnapshotPayload(payload).ciphertext,
      ),
      deterministic("payload_cbor/deterministic", payload),
      check("payload_cbor/inputs", () => {
        const p = decodeSnapshotPayload(payload);
        return (
          (p.dataEpoch === BigInt(Number(c.inputs?.data_epoch)) &&
            p.snapshotSeq === BigInt(Number(c.inputs?.snapshot_sequence)) &&
            bytesEqual(p.controlHead, hexOf(c.inputs, "control_head"))) ||
          "payload fields differ from inputs data_epoch, snapshot_sequence, control_head"
        );
      }),
      deterministic("protected_header_cbor/deterministic", protectedHeader),
      sameBytes(
        "protected_header_cbor",
        protectedHeader,
        () => parseSignedObject(cose).protectedBytes,
      ),
      bytesCheck(
        "sig_structure_cbor",
        hexOf(e, "sig_structure_cbor"),
        sigStructureBytes(protectedHeader, payload),
      ),
      ...signed.checks,
      bytesCheck("snapshot_id", hexOf(e, "snapshot_id"), objectId(cose)),
    ],
  };
};

const inviteUri: Handler = (c, context) => {
  const e = c.expected;
  const secret = hexOf(e, "secret_cbor");
  const fixtures = context.suite.fixtures as { resource?: { id?: unknown } } | undefined;
  return {
    checks: [
      deterministic("secret_cbor/deterministic", secret),
      equalCheck("secret_b64url", b64Of(e, "secret_b64url"), toBase64url(secret)),
      check("resource_b64url", () => {
        const actual = toBase64url(hexOf(fixtures?.resource as Fields, "id"));
        return actual === b64Of(e, "resource_b64url") || `actual ${actual}`;
      }),
      check("grant_id_b64url/control-record", () => {
        const id = fromBase64url(b64Of(e, "grant_id_b64url"));
        const match = context.suite.cases.some(
          (r) =>
            r.type === "bytes" &&
            r.kind === "control_record" &&
            bytesEqual(hexOf(r.expected, "record_id"), id),
        );
        return match || "names no Control Record of this suite";
      }),
    ],
    pending: ["secret_cbor/typed", "uri/assemble"],
  };
};

/** The persistent objects a message carries, with the parser for each (§39-§57, §36). */
function embeddedObjects(m: AnyMessage): {
  readonly field: string;
  readonly bytes: Uint8Array;
  readonly parse: (b: Uint8Array) => unknown;
}[] {
  const list = (field: string, objects: readonly Uint8Array[], parse: (b: Uint8Array) => unknown) =>
    objects.map((bytes, i) => ({ field: `${field}[${i}]`, bytes, parse }));
  switch (m.type) {
    case "AUTH":
      return list("proof", [m.body.proof], parseSignedObject);
    case "RESOURCE_HOST":
      return list("genesis", [m.body.genesis], decodeControlRecord);
    case "CONTROL_BATCH":
      return list("records", m.body.objects, decodeControlRecord);
    case "CONTROL_PUT":
      return list("record", [m.body.record], decodeControlRecord);
    case "DATA_BATCH":
    case "DATA_PUT":
      return list("units", m.body.objects, parseDataUnit);
    case "KEY_PACKAGE_BATCH":
    case "KEY_PACKAGE_PUT":
      return list("packages", m.body.objects, parseKeyPackage);
    case "SNAPSHOT":
    case "SNAPSHOT_PUT":
      return list("snapshot", [m.body.snapshot], parseSnapshot);
    default:
      return [];
  }
}

/** The exact bytes of every signed object the suite publishes. */
function publishedObjects(context: HandlerContext): Set<string> {
  const out = new Set<string>();
  for (const c of context.suite.cases)
    for (const [field, value] of Object.entries(c.expected ?? {}))
      if (/cose_sign1$/.test(field) && typeof (value as { hex?: unknown })?.hex === "string")
        out.add((value as { hex: string }).hex);
  return out;
}

/** The message ID (field 1) of a message's bytes. */
const messageIdOf = (bytes: Uint8Array): string => toHex(decodeEnvelope(bytes).messageId);

/**
 * LFCP-026. The message decodes with the typed codec (envelope, §33 type
 * and §34-§61 body) and re-encodes to its exact bytes; every persistent
 * object it carries parses with its own parser and is byte for byte a
 * published object (never re-encoded). An ACK names the type of the
 * request it correlates to (A1); NACK(CONTROL_HEAD_MISMATCH) carries the
 * current head the coordinator reports for the correlated CONTROL_PUT
 * (G-MSG5). The AUTH transcript and proof binding are LFCP-027.
 */
const wireMessage: Handler = (c, context) => {
  const e = c.expected;
  const bytes = hexOf(e, "message_cbor");
  const checks: Check[] = [deterministic("message_cbor/deterministic", bytes)];
  const pending: string[] = [];
  let message: AnyMessage | undefined;
  try {
    message = decodeMessage(bytes);
    checks.push(bytesCheck("message_cbor/typed", bytes, encodeMessage(message)));
  } catch (err) {
    checks.push({ name: "message_cbor/typed", ok: false, message: describeError(err) });
  }
  if (message !== undefined) {
    const m = message;
    const objects = embeddedObjects(m);
    if (objects.length > 0) {
      const published = publishedObjects(context);
      checks.push(
        check("message_cbor/objects", () => {
          for (const o of objects) {
            o.parse(o.bytes);
            if (!published.has(toHex(o.bytes))) return `${o.field} is not a published object`;
          }
          return true;
        }),
      );
    }
    if (m.type === "ACK" && m.correlationId !== undefined) {
      const request = context.suite.cases.find(
        (x) =>
          x.type === "bytes" &&
          x.kind === "wire_message" &&
          messageIdOf(hexOf(x.expected, "message_cbor")) === toHex(m.correlationId as Uint8Array),
      );
      checks.push(
        check("message_cbor/ack-request-type", () => {
          if (request === undefined) return "no published request has the correlation ID";
          return (
            decodeEnvelope(hexOf(request.expected, "message_cbor")).code === m.body.requestType ||
            "the ACK does not name the request's type"
          );
        }),
      );
    }
    // LFCP-028: a sender emits each live Have list normalized (§28, §48).
    const lists =
      m.type === "DATA_HAVE" || m.type === "RESOURCE_OPEN"
        ? [m.body.haves]
        : m.type === "RESOURCE_OPENED"
          ? [m.body.haves, ...(m.body.snapshot ? [m.body.snapshot.frontier] : [])]
          : [];
    const text = (v: unknown) =>
      JSON.stringify(v, (_k, x) =>
        x instanceof Uint8Array ? toHex(x) : typeof x === "bigint" ? String(x) : x,
      );
    if (lists.some((l) => l.length > 0))
      checks.push(
        check(
          "message_cbor/live-haves-normalized",
          () =>
            lists.every(
              (l) =>
                text(liveHavesOf(normalizeLiveHaves(l))) ===
                text([...l].sort((a, b) => (toHex(a.principalId) < toHex(b.principalId) ? -1 : 1))),
            ) || "a live Have list is not in normalized form",
        ),
      );
    if (m.type === "NACK" && m.body.code === ERROR_CODE.CONTROL_HEAD_MISMATCH)
      checks.push(check("message_cbor/current-head", () => nackCurrentHead(context, m)));
  }
  if (has(e, "auth_transcript_cbor")) {
    const transcript = hexOf(e, "auth_transcript_cbor");
    checks.push(
      deterministic("auth_transcript_cbor/deterministic", transcript),
      sameBytes("auth_transcript_cbor/construct", transcript, () =>
        authTranscript(handshakeFields(context)),
      ),
    );
  }
  if (has(e, "auth_proof_cose_sign1")) {
    const proof = hexOf(e, "auth_proof_cose_sign1");
    const transcript = hexOf(e, "auth_transcript_cbor");
    checks.push(
      ...signedObject(
        "auth_proof_cose_sign1",
        context,
        proof,
        (b) => ({ signed: parseSignedObject(b), payload: null }),
        kidOf,
        transcript,
      ).checks,
      check("auth_proof_cose_sign1/session-binding", () => {
        if (message?.type !== "AUTH") return "the message is not an AUTH";
        if (!bytesEqual(message.body.proof, proof)) return "the AUTH body does not carry the proof";
        const hello = handshakeMessage(context, "HELLO");
        const v = verifyAuthProof(proof, handshakeFields(context), hello.body.principal);
        return v.valid || `the proof does not bind this session: ${v.reason}`;
      }),
      check("handshake/replay", () => replayHandshake(context)),
    );
  }
  return { checks, pending };
};

/** The published handshake message of `type` (one each of HELLO, CHALLENGE, AUTH, READY). */
function handshakeMessage<T extends "HELLO" | "CHALLENGE" | "AUTH" | "READY">(
  context: HandlerContext,
  type: T,
): LfcpMessage<T> {
  for (const c of context.suite.cases) {
    if (c.type !== "bytes" || c.kind !== "wire_message") continue;
    const m = decodeMessage(hexOf(c.expected, "message_cbor"));
    if (m.type === type) return m as LfcpMessage<T>;
  }
  throw new Error(`the suite has no ${type} message`);
}

/** The §36 transcript fields of the published handshake: HELLO's nonce and Principal, CHALLENGE's values. */
function handshakeFields(context: HandlerContext): AuthTranscriptFields {
  const hello = handshakeMessage(context, "HELLO").body;
  const challenge = handshakeMessage(context, "CHALLENGE").body;
  return {
    sessionId: challenge.sessionId,
    clientNonce: hello.clientNonce,
    serverNonce: challenge.serverNonce,
    serverId: challenge.serverId,
    principalId: hello.principal.principalId,
  };
}

/**
 * LFCP-027: the published HELLO, CHALLENGE, AUTH and READY re-created by
 * the pure client and server handshakes, byte for byte once the vectors'
 * message IDs are substituted. The nonces and session ID come from a
 * test-only random source that returns the published values; the server ID
 * and READY parameters are the server's configuration.
 */
function replayHandshake(context: HandlerContext): true | string {
  const published = {
    HELLO: handshakeMessage(context, "HELLO"),
    CHALLENGE: handshakeMessage(context, "CHALLENGE"),
    AUTH: handshakeMessage(context, "AUTH"),
    READY: handshakeMessage(context, "READY"),
  };
  const queue =
    (...values: Uint8Array[]) =>
    () => {
      const next = values.shift();
      if (next === undefined) throw new Error("the replay asked for more random bytes");
      return next;
    };
  const signer = signerFor(context, published.HELLO.body.principal.principalId);
  const ready = published.READY.body;
  const client = {
    signer,
    wireProfiles: published.HELLO.body.wireProfiles,
    ...(published.HELLO.body.dataProfiles
      ? { dataProfiles: published.HELLO.body.dataProfiles }
      : {}),
    random: queue(published.HELLO.body.clientNonce),
  };
  const server = {
    serverId: published.CHALLENGE.body.serverId,
    wireProfiles: [WIRE_PROFILE],
    maxMessageBytes: ready.maxMessageBytes,
    durability: ready.durability,
    heartbeatMs: ready.heartbeatMs,
    ...(ready.extensions ? { extensions: ready.extensions } : {}),
    random: queue(published.CHALLENGE.body.serverNonce, published.CHALLENGE.body.sessionId),
  };
  const same = (ours: AnyMessage | undefined, theirs: AnyMessage): boolean =>
    ours !== undefined &&
    bytesEqual(
      encodeMessage({
        ...ours,
        messageId: theirs.messageId,
        ...(theirs.correlationId ? { correlationId: theirs.correlationId } : {}),
      } as AnyMessage),
      encodeMessage(theirs),
    );
  const start = startClientHandshake(client);
  if (!same(start.send[0], published.HELLO)) return "HELLO differs";
  const s1 = serverReceive(startServerSession(), published.HELLO, server);
  if (!same(s1.send[0], published.CHALLENGE)) return "CHALLENGE differs";
  const c1 = clientReceive(start.session, published.CHALLENGE, client);
  if (!same(c1.send[0], published.AUTH)) return "AUTH differs";
  const s2 = serverReceive(s1.session, published.AUTH, server);
  if (!same(s2.send[0], published.READY)) return "READY differs";
  const c2 = clientReceive(c1.session, published.READY, client);
  if (s2.session.phase !== "READY" || c2.session.phase !== "READY")
    return "the handshake did not reach READY on both sides";
  return true;
}

/**
 * G-MSG5: the NACK correlates to a CONTROL_PUT vector that expects
 * CONTROL_HEAD_MISMATCH; proposing that put at its context head must report
 * exactly the NACK's details as the current head.
 */
function nackCurrentHead(context: HandlerContext, nack: LfcpMessage<"NACK">): true | string {
  const correlation = nack.correlationId;
  if (correlation === undefined) return "the NACK has no correlation ID";
  const put = context.suite.cases.find((x) => {
    const code = (x.expected as { error?: { code?: unknown } }).error?.code;
    return (
      x.type === "validation" &&
      x.kind === "control_put" &&
      code === "CONTROL_HEAD_MISMATCH" &&
      messageIdOf(hexOf(x.inputs, "message_cbor")) === toHex(correlation)
    );
  });
  if (put === undefined) return "no CONTROL_PUT vector with this message ID expects the mismatch";
  const request = decodeMessage(hexOf(put.inputs, "message_cbor"));
  if (request.type !== "CONTROL_PUT") return "the correlated request is not a CONTROL_PUT";
  const state = publishedView(context).stateAt(
    referenced(context, (put.context as { current_control_head?: unknown })?.current_control_head),
  );
  if (state === undefined) return "the put's context head is not on the chain";
  const result = proposeControlPut(state, request.body);
  if (result.kind !== "head-mismatch") return `the put is ${result.kind}, not a head mismatch`;
  return (
    bytesEqual(result.currentHead, nack.body.details as Uint8Array) ||
    "the NACK details are not the current head"
  );
}

// ---------------------------------------------------------------------------
// validation cases

/**
 * Runs a received object through this SDK's layers (structure, then the
 * signature against the payload's expected signer) and returns the wire
 * code it fails with, or null when every implemented layer accepts it.
 */
function receive<P>(
  context: HandlerContext,
  cose: Uint8Array,
  parse: (bytes: Uint8Array) => Parsed<P>,
  signerOf: (p: Parsed<P>) => PrincipalId,
): string | null {
  let parsed: Parsed<P>;
  try {
    parsed = parse(cose);
  } catch (e) {
    return wireCodeOf(e);
  }
  const v = verifySignedObject(parsed.signed, signerFor(context, signerOf(parsed)).descriptor);
  return v.valid ? null : SIGNATURE_FAILURE;
}

/** The outcome check when a layer rejects; when all implemented layers accept, the outcome is pending. */
function negative(c: VectorCase, actual: string | null): { checks: Check[]; pending: string[] } {
  const e = c.expected as { valid?: unknown; error?: { code?: unknown } };
  if (e.valid === true) {
    const ok: Check =
      actual === null
        ? { name: "outcome", ok: true }
        : { name: "outcome", ok: false, message: `expected acceptance, actual ${actual}` };
    return { checks: [ok], pending: [] };
  }
  const expected = typeof e.error?.code === "string" ? e.error.code : null;
  if (actual === null)
    return { checks: [{ name: "structure-and-signature", ok: true }], pending: ["outcome"] };
  return { checks: [outcomeCheck("outcome", expected, actual)], pending: [] };
}

/**
 * A layer applied after structure and signature accept an object: the wire
 * code it fails with, or null (the Key Package opening, LFCP-024).
 */
type AfterReceive<P> = (
  context: HandlerContext,
  parsed: Parsed<P>,
  vector: VectorCase,
) => string | null | Promise<string | null>;

/** The published Data Unit case whose unit_id is `unitId` (for vectors that name a unit by ID). */
function publishedUnit(context: HandlerContext, unitId: Uint8Array): Uint8Array | undefined {
  const c = context.suite.cases.find(
    (x) =>
      x.type === "bytes" &&
      x.kind === "data_unit" &&
      bytesEqual(hexOf(x.expected, "unit_id"), unitId),
  );
  return c === undefined ? undefined : hexOf(c.expected, "cose_sign1");
}

function signedNegative<P>(
  parse: (bytes: Uint8Array) => Parsed<P>,
  signerOf: (p: Parsed<P>) => PrincipalId,
  after?: AfterReceive<P>,
): Handler {
  return async (c, context) => {
    const inputs = c.inputs;
    const extra: Check[] = [];
    let cose: Uint8Array | undefined;
    if (has(inputs, "cose_sign1")) cose = hexOf(inputs, "cose_sign1");
    else if (has(inputs, "conflicting_D2_cose")) cose = hexOf(inputs, "conflicting_D2_cose");
    else if (has(inputs, "unit_id")) {
      // The vector names a published unit by its ID (stale_epoch: D3).
      cose = publishedUnit(context, hexOf(inputs, "unit_id"));
      if (cose !== undefined)
        extra.push(bytesCheck("inputs.unit_id", hexOf(inputs, "unit_id"), objectId(cose)));
    }
    if (cose === undefined) return { checks: [], pending: ["outcome"] }; // no object to receive
    if (has(inputs, "record_id"))
      extra.push(bytesCheck("inputs.record_id", hexOf(inputs, "record_id"), objectId(cose)));
    if (has(inputs, "conflicting_D2_id"))
      extra.push(
        bytesCheck("inputs.conflicting_D2_id", hexOf(inputs, "conflicting_D2_id"), objectId(cose)),
      );
    if (has(inputs, "noncanonical_aad_cbor")) {
      extra.push(
        check(
          "inputs.noncanonical_aad_cbor/not-deterministic",
          () => !isDeterministic(hexOf(inputs, "noncanonical_aad_cbor")),
        ),
      );
    }
    let actual = receive(context, cose, parse, signerOf);
    if (actual === null && after !== undefined) actual = await after(context, parse(cose), c);
    const result = negative(c, actual);
    return { checks: [...extra, ...result.checks], pending: result.pending };
  };
}

/**
 * LFCP-024: a received Key Package opened with the recipient key its
 * vector's context names (hpke_recipient_mismatch_KP0: CAROL's key for a
 * package sealed to BOB). Opening failures are client-local (N5), so the
 * outcome has no wire code: the vector requires failure only.
 */
const keyPackageOpen: AfterReceive<KeyPackagePayload> = async (context, parsed, vector) => {
  const ref = (vector.context as { recipient_x25519_private?: unknown } | undefined)
    ?.recipient_x25519_private;
  if (ref === undefined) return null;
  const chain = validateControlChain(publishedChain(context));
  if (chain.kind !== "linear") return null;
  const commitment = chain.state.epochs.get(String(parsed.payload.dataEpoch))?.dekCommitment;
  if (commitment === undefined) return "MISSING_DEPENDENCY";
  const descriptor = principals(context).get(toHex(parsed.payload.recipient))?.descriptor;
  if (descriptor === undefined) return "CLIENT_LOCAL:UNKNOWN_RECIPIENT";
  try {
    await openKeyPackage(
      parsed,
      { descriptor, agreement: importAgreementKey(referenced(context, ref)) },
      commitment,
    );
    return null;
  } catch (e) {
    return `CLIENT_LOCAL:${e instanceof LfcpError ? e.code : String(e)}`;
  }
};

/** The vector outcome of a received Data Unit: null when accepted, else a code or a client-local marker. */
function dataUnitOutcome(r: ReceivedDataUnit<unknown>): string | null {
  switch (r.kind) {
    case "accepted":
    case "duplicate":
      return null;
    case "rejected":
    case "equivocation":
      return r.wireCode;
    case "quarantined":
      return r.code;
    case "held":
      return `REPORT:${r.reason}`;
    case "local-failure":
      return `CLIENT_LOCAL:${r.reason}`;
  }
}

/** The vector disposition of a received Data Unit (lfcp-vector-format/1). */
function dataUnitDisposition(r: ReceivedDataUnit<unknown>): string {
  switch (r.kind) {
    case "accepted":
    case "duplicate":
      return "accept";
    case "held":
      return "report";
    case "quarantined":
      return "quarantine";
    case "equivocation":
      return "equivocation";
    case "rejected":
    case "local-failure":
      return "reject";
  }
}

/**
 * LFCP-025: a received Data Unit through the full receive pipeline
 * (receiveDataUnit) on the published chain, with the fixture DEKs. The
 * outcome must carry the vector's code and, when it names one, its
 * disposition (report = held, §26.2 / G-DP1; quarantine =
 * STALE_DATA_EPOCH; reject, client-local AEAD failures included, N3).
 *
 * actor_equivocation first receives the published units up to the one in
 * inputs.original_D2_id, and both IDs must be reported. noncanonical_aad_D1
 * must open under its non-deterministic AAD, showing that only the AAD
 * encoding fails.
 */
const structureAndSignature = signedNegative(parseDataUnit, (p) => expectedSignerOf(p.payload));

const dataUnitNegative: Handler = async (c, context) => {
  // A suite without a valid Control Chain (the runner self-tests) has no
  // authority or epochs to evaluate: only structure and signature run.
  if (validateControlChain(publishedChain(context)).kind !== "linear")
    return structureAndSignature(c, context);
  const inputs = c.inputs;
  const checks: Check[] = [];
  let cose: Uint8Array | undefined;
  if (has(inputs, "cose_sign1")) cose = hexOf(inputs, "cose_sign1");
  else if (has(inputs, "conflicting_D2_cose")) cose = hexOf(inputs, "conflicting_D2_cose");
  else if (has(inputs, "unit_id")) {
    cose = publishedUnit(context, hexOf(inputs, "unit_id"));
    if (cose !== undefined)
      checks.push(bytesCheck("inputs.unit_id", hexOf(inputs, "unit_id"), objectId(cose)));
  }
  if (cose === undefined) throw new Error("the vector names no Data Unit");
  if (has(inputs, "conflicting_D2_id"))
    checks.push(
      bytesCheck("inputs.conflicting_D2_id", hexOf(inputs, "conflicting_D2_id"), objectId(cose)),
    );
  const receiver = dataReceiver(context);
  if (has(inputs, "original_D2_id")) {
    const original = toHex(hexOf(inputs, "original_D2_id"));
    for (const u of context.suite.cases) {
      if (u.type !== "bytes" || u.kind !== "data_unit") continue;
      await receiver.receive(hexOf(u.expected, "cose_sign1"));
      if (toHex(hexOf(u.expected, "unit_id")) === original) break;
    }
  }
  if (has(inputs, "noncanonical_aad_cbor")) {
    const aad = hexOf(inputs, "noncanonical_aad_cbor");
    checks.push(
      check("inputs.noncanonical_aad_cbor/not-deterministic", () => !isDeterministic(aad)),
    );
    checks.push(
      check("inputs.noncanonical_aad_cbor/opens", () => {
        const p = parseDataUnit(cose).payload;
        const key = deriveActorDataKey(
          dekForEpoch(context, p.dataEpoch),
          p.resourceId,
          p.dataEpoch,
          p.actor,
        );
        decryptDataUnit(key, p.actorSeq, aad, p.ciphertext);
        return true;
      }),
    );
  }
  const received = await receiver.receive(cose);
  if (received.kind === "equivocation" && has(inputs, "original_D2_id"))
    checks.push(
      check("outcome/unit-ids", () => {
        const ids = received.unitIds.map(toHex);
        return (
          (ids.length === 2 &&
            ids.includes(toHex(hexOf(inputs, "original_D2_id"))) &&
            ids.includes(toHex(objectId(cose)))) ||
          `reported ${ids.join(", ")}`
        );
      }),
    );
  const disposition = (c.expected as { disposition?: unknown }).disposition;
  if (typeof disposition === "string")
    checks.push(equalCheck("outcome/disposition", disposition, dataUnitDisposition(received)));
  const outcome = negative(c, dataUnitOutcome(received));
  return { checks: [...checks, ...outcome.checks], pending: outcome.pending };
};

/**
 * LFCP-026: a received message through decodeMessage; the outcome is its
 * §62 code (messageErrorWireCode). Semantic rules beyond the codec, such
 * as live Have ranges (§48, LFCP-028), are named pending by the case.
 */
const wireMessageNegative: Handler = (c) => {
  let actual: string | null = null;
  try {
    decodeMessage(hexOf(c.inputs, "message_cbor"));
  } catch (err) {
    actual = messageErrorWireCode(err);
  }
  return negative(c, actual);
};

const snapshotStructure = signedNegative(parseSnapshot, (p) => expectedSignerOf(p.payload));

/**
 * LFCP-029: a received Snapshot through checkSnapshot on the published
 * chain (structure, publisher signature, snapshot/publish at its head, the
 * epoch, G-EP4); a suite without a chain runs structure and signature only.
 */
const snapshotNegative: Handler = (c, context) => {
  if (validateControlChain(publishedChain(context)).kind !== "linear")
    return snapshotStructure(c, context);
  const r = checkSnapshot(publishedView(context), hexOf(c.inputs, "cose_sign1"));
  return negative(c, r.kind === "valid" ? null : r.wireCode);
};

/**
 * LFCP-WIRE-01 §10.5.1, §106: the shared strict-Ed25519 cases through
 * verifyEd25519 alone, without an LFCP object around the signature.
 */
const ed25519Signature: Handler = (c) =>
  negative(
    c,
    verifyEd25519(
      hexOf(c.inputs, "public_key"),
      hexOf(c.inputs, "message"),
      hexOf(c.inputs, "signature"),
    )
      ? null
      : SIGNATURE_FAILURE,
  );

const principalNegative: Handler = (c) => {
  let actual: string | null = null;
  try {
    decodePrincipalDescriptor(hexOf(c.inputs, "descriptor_cbor"));
  } catch (e) {
    actual = wireCodeOf(e);
  }
  return negative(c, actual);
};

export const WIRE_HANDLERS: Readonly<Record<string, Handler>> = {
  "bytes/principal": principal,
  "bytes/control_record": controlRecord,
  "bytes/owner_transfer": ownerTransfer,
  "bytes/key_package": keyPackage,
  "bytes/dek_commitment": dekCommitments,
  "bytes/data_unit": dataUnit,
  "bytes/snapshot": snapshot,
  "bytes/invite_uri": inviteUri,
  "bytes/wire_message": wireMessage,
  "validation/data_unit": dataUnitNegative,
  "validation/control_record": controlRecordNegative,
  "validation/control_put": controlPutNegative,
  "validation/key_package": signedNegative(
    parseKeyPackage,
    (p) => expectedSignerOf(p.payload),
    keyPackageOpen,
  ),
  "validation/snapshot": snapshotNegative,
  "validation/principal": principalNegative,
  "validation/wire_message": wireMessageNegative,
  "validation/ed25519_signature": ed25519Signature,
};
