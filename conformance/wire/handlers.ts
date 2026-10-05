// LFCP-TEST-VECTORS-01 handlers for sdk-ts (LFCP-017; extended by each later task).
//
// One handler per "<type>/<kind>". A handler checks what the SDK implements
// today and names, as pending parts, what later tasks implement (the owner
// of each part is in pending.json). Values come only from the loaded suite.

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
  dekCommitment,
  deriveActorDataKey,
  deriveSnapshotKey,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  type ResourceDEK,
  snapshotNonce,
} from "@openlfcp/crypto";
import {
  type ControlRecord,
  canonicalFrontierFromCbor,
  classifyDataUnit,
  controlPutBodyFromCbor,
  type DataUnitPayload,
  decodeControlRecord,
  decodeControlRecordPayload,
  decodeDataUnitPayload,
  decodeKeyPackagePayload,
  decodePrincipalDescriptor,
  decodeSnapshotPayload,
  derivePrincipalId,
  encodeControlRecordPayload,
  encodePrincipalDescriptor,
  expectedSignerOf,
  type KeyPackagePayload,
  type KeyPackageRecipient,
  keyPackageHpkeAad,
  keyPackageHpkeInfo,
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
  type Signer,
  signControlRecord,
  signObject,
  sigStructureBytes,
  validateControlChain,
  verifyGenesis,
  verifyKeyPackage,
  verifySignedObject,
} from "@openlfcp/wire";
import {
  type CborValue,
  decodeStrict,
  encode,
  isCborMap,
  isDeterministic,
} from "@openlfcp/wire/cbor";
import { bytesCheck, check, describeError, equalCheck, outcomeCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, VectorCase, VectorSuite } from "../runner.js";
import { SIGNATURE_FAILURE, wireCodeOf } from "./error-map.js";
import { aeadSeal, sealWithRawSkE } from "./hpke-raw-ske.js";

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
 */
const controlRecordNegative: Handler = (c, context) => {
  const cose = hexOf(c.inputs, "cose_sign1");
  const result = validateControlChain([...publishedChain(context), cose]);
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
 * LFCP-022: a CONTROL_PUT against the coordinator's state at the vector's
 * current head. Only the §47 body is decoded (field 4 of the envelope,
 * read with generic CBOR); the envelope codec itself is LFCP-026.
 */
const controlPutNegative: Handler = (c, context) => {
  const message = decodeStrict(hexOf(c.inputs, "message_cbor"));
  const field = (k: number): CborValue | undefined =>
    isCborMap(message) ? message.entries.find(([key]) => key === k)?.[1] : undefined;
  const checks: Check[] = [equalCheck("inputs.message_cbor/type", 23, field(0))]; // §33: 23 = CONTROL_PUT
  const ctx = c.context as { current_control_head?: unknown } | undefined;
  const chain = validateControlChain(publishedChain(context));
  if (chain.kind !== "linear") throw new Error("the published Control Chain does not validate");
  const head = referenced(context, ctx?.current_control_head);
  const state = chain.stateAt(head);
  if (state === undefined) throw new Error("the context head is not on the published chain");
  const result = proposeControlPut(state, controlPutBodyFromCbor(field(4) as CborValue));
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
 * LFCP-024. Every HPKE field is checked: info and AAD built from the
 * payload (§25.1); enc = X25519(skE); the shared secret, enc and
 * ciphertext reproduced through the library from the published skE
 * (test-only wrapper, hpke-raw-ske.ts); the published key and base_nonce
 * produce the ciphertext through the suite AEAD; the package opens for its
 * recipient to the epoch DEK with the chain's commitment; and the package
 * is authorized at its head (§25.2).
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
  const skE = hexOf(c.inputs, "hpke_ephemeral_private");
  const recipient = recipientKeys(context, p.recipient);
  const dek = dekForEpoch(context, p.dataEpoch);
  const dekBytes = exportSecretKeyBytes(dek);
  const seal = await sealWithRawSkE(skE, recipient.descriptor.x25519PublicKey, dekBytes, info, aad);
  const published = await aeadSeal(
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
    sameBytes("hpke_enc/payload-field", hexOf(e, "hpke_enc"), () => p.hpkeEnc),
    bytesCheck("hpke_enc/derive", hexOf(e, "hpke_enc"), importAgreementKey(skE).publicKey),
    bytesCheck("hpke_enc/seal", hexOf(e, "hpke_enc"), seal.enc),
    bytesCheck("hpke_shared_secret/derive", hexOf(e, "hpke_shared_secret"), seal.sharedSecret),
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

const dataUnit: Handler = (c, context) => {
  const e = c.expected;
  const payload = hexOf(e, "payload_cbor");
  const cose = hexOf(e, "cose_sign1");
  const signed = signedObject(
    "cose_sign1",
    context,
    cose,
    parseDataUnit,
    (p) => expectedSignerOf(p.payload),
    payload,
  );
  return {
    checks: [
      sameBytes("actor_key/derive", hexOf(e, "actor_key"), () => {
        const p = decodeDataUnitPayload(payload);
        const dek = dekForEpoch(context, p.dataEpoch);
        return exportSecretKeyBytes(deriveActorDataKey(dek, p.resourceId, p.dataEpoch, p.actor));
      }),
      sameBytes("nonce/derive", hexOf(e, "nonce"), () =>
        dataUnitNonce(decodeDataUnitPayload(payload).actorSeq),
      ),
      deterministic("aad_cbor/deterministic", hexOf(e, "aad_cbor")),
      sameBytes(
        "ciphertext/payload-field",
        hexOf(e, "ciphertext"),
        () => decodeDataUnitPayload(payload).ciphertext,
      ),
      deterministic("payload_cbor/deterministic", payload),
      check("payload_cbor/decode", () => decodeDataUnitPayload(payload).kind === "data-unit"),
      ...signed.checks,
      bytesCheck("unit_id", hexOf(e, "unit_id"), objectId(cose)),
    ],
    pending: ["aad_cbor/construct", "ciphertext/encrypt"],
  };
};

const snapshot: Handler = (c, context) => {
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
  return {
    checks: [
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
    pending: ["aad_cbor/construct", "ciphertext/encrypt"],
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

const wireMessage: Handler = (c, context) => {
  const e = c.expected;
  const checks: Check[] = [deterministic("message_cbor/deterministic", hexOf(e, "message_cbor"))];
  const pending = ["message_cbor/typed"];
  if (has(e, "auth_transcript_cbor")) {
    checks.push(
      deterministic("auth_transcript_cbor/deterministic", hexOf(e, "auth_transcript_cbor")),
    );
    pending.push("auth_transcript_cbor/construct");
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
    );
    pending.push("auth_proof_cose_sign1/session-binding");
  }
  return { checks, pending };
};

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
 * code it fails with, or null. LFCP-023 adds the epoch cutoff for Data Units.
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

/**
 * LFCP-023: a received Data Unit against the epoch cutoff of the latest
 * published Control state (C6; G-EP1). A quarantined unit is
 * STALE_DATA_EPOCH (§19.1, §75); an unknown head or epoch is the reject's
 * code (G-EP2).
 */
const dataUnitEpoch: AfterReceive<DataUnitPayload> = (context, parsed) => {
  // A suite without a valid Control Chain has no cutoff to apply; the
  // published chain's own validity is asserted by every control_record case.
  const chain = validateControlChain(publishedChain(context));
  if (chain.kind !== "linear") return null;
  const c = classifyDataUnit(chain, parsed.payload);
  return c.kind === "accept" ? null : c.kind === "quarantine" ? c.code : c.wireCode;
};

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
  "validation/data_unit": signedNegative(
    parseDataUnit,
    (p) => expectedSignerOf(p.payload),
    dataUnitEpoch,
  ),
  "validation/control_record": controlRecordNegative,
  "validation/control_put": controlPutNegative,
  "validation/key_package": signedNegative(
    parseKeyPackage,
    (p) => expectedSignerOf(p.payload),
    keyPackageOpen,
  ),
  "validation/snapshot": signedNegative(parseSnapshot, (p) => expectedSignerOf(p.payload)),
  "validation/principal": principalNegative,
};
