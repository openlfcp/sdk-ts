// LFCP-IDENTITY-TEST-VECTORS-01 handlers (IDENTITY-PROFILE-01 §12.2 ID-01 to
// ID-04, LFCP-04-412): every case of the wire identity corpus through
// @openlfcp/wire and @openlfcp/client, with the case's outcome in the
// lfcp-identity-outcomes/1 vocabulary (outcome, accepted IDs, post-state)
// as the handler report, and checks of that report against the corpus.
//
// The report is what sdk-ts derived; `expected` is read only by the checks
// and, where the corpus states a query rather than an answer (the
// Principals of `queries`, the facts a Key Package case names, the
// candidates of the rotator test), for the question asked.

import { readersAt, rotatorTest } from "@openlfcp/client";
import { bytesEqual, fromHex, type PrincipalId, principalId, toHex } from "@openlfcp/core";
import { importAgreementKey, importResourceDEK, importSigningKey, sha256 } from "@openlfcp/crypto";
import {
  ABILITY,
  activeDevice,
  actsFor,
  type CertificateChain,
  type ControlRecord,
  type ControlState,
  canDistributeKey,
  certificateChainFromCbor,
  checkChainAuthority,
  checkDataUnit,
  checkSnapshot,
  type DeviceCertificatePayload,
  decodeControlRecord,
  decodePrincipalDescriptor,
  deviceChainChecks,
  encodeMessage,
  encodePrincipalDescriptor,
  hasAbility,
  InMemorySeenUnits,
  isBound,
  isExposingRevocation,
  objectId,
  parseDataUnit,
  parseDeviceCertificate,
  parseKeyPackage,
  parseSignedObject,
  principalDescriptorFromKeys,
  receiveDataUnit,
  revocationOf,
  revokedReaderPrefix,
  rootOf,
  rootStanding,
  type SignedObject,
  signDeviceCertificate,
  signObject,
  sigStructureBytes,
  validateControlChain,
  verifyChain,
  verifyKeyPackage,
  verifySignedObject,
} from "@openlfcp/wire";
import { cborMap, decodeStrict, encode } from "@openlfcp/wire/cbor";
import { bytesCheck, check, equalCheck } from "../checks.js";
import type { Check, Handler, HandlerResult, VectorCase } from "../runner.js";
import { contextOf, idOf, type Linear, party, recordsAt, wire, wireCase } from "./corpus.js";
import { certificateLabel, principalLabel, resourceLabel } from "./labels.js";

// biome-ignore lint/suspicious/noExplicitAny: corpus JSON
type Json = any;
type Report = Record<string, unknown>;

// ---------------------------------------------------------------------------
// shared

const hexOf = (v: Json): Uint8Array => fromHex((v as { hex: string }).hex);
const num = (n: bigint): number | string =>
  n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString();
const accept = (ids: readonly Uint8Array[], postState: unknown = null): Report => ({
  outcome: "accept",
  accepted_ids: ids.map((id) => toHex(id)),
  post_state: postState,
});
const refuse = (code: string, detail?: string, extra: Report = {}): Report => ({
  outcome: code,
  diagnostic: null,
  ...(detail === undefined ? {} : { detail }),
  accepted_ids: [],
  post_state: null,
  ...extra,
});
const errorCode = (e: unknown): string => {
  const code = (e as { code?: unknown })?.code;
  return typeof code === "string" ? code : String(e);
};
/** A structural failure while decoding is MALFORMED_MESSAGE (§62 class 1). */
const malformed = (e: unknown) => refuse("MALFORMED_MESSAGE", `${errorCode(e)}: ${String(e)}`);

/** The case IDs of every Control Record, by record ID hex (the first case that carries it). */
const RECORD_CASES = new Map<string, string>();
for (const c of wire.cases as readonly Json[])
  if (c.kind === "control_record" && c.inputs?.record_id !== undefined)
    if (!RECORD_CASES.has(c.inputs.record_id.hex)) RECORD_CASES.set(c.inputs.record_id.hex, c.id);
const recordLabel = (id: Uint8Array): string => RECORD_CASES.get(toHex(id)) ?? toHex(id);

/** The verdict of a list of records as a chain: the linear chain, or its wire code. */
function chainOrCode(records: readonly Uint8Array[]): Linear | { readonly code: string } {
  const r = validateControlChain([...records]);
  if (r.kind === "linear") return r;
  return { code: r.wireCode };
}

/** The receiver's Control state for a Data Plane case: the chain through context.latest. */
function latestChain(c: VectorCase): Linear {
  const latest = (c.context as Json)?.latest as { case?: string } | undefined;
  const records =
    latest?.case !== undefined && wireCase(latest.case).kind === "control_record"
      ? recordsAt(latest.case)
      : contextOf(c.id);
  const r = chainOrCode(records);
  if ("code" in r) throw new Error(`the receiver's chain of ${c.id} is ${r.code}`);
  return r;
}

const sortedLabels = (ids: Iterable<Uint8Array>) => [...ids].map(principalLabel).sort();
const numbers = (codes: readonly bigint[]) =>
  [...codes].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map(num);

/** One device's derived state (§79, §80.1), in the corpus's vocabulary. */
export function deviceRow(state: ControlState, id: string): Report {
  const d = state.devices.get(id);
  if (d === undefined) throw new Error(`no device ${id}`);
  const p = principalId(fromHex(id));
  const own = revocationOf(state, d.root, p) !== undefined;
  return {
    root: principalLabel(d.root),
    kind: d.kind,
    mask: numbers(d.mask),
    scope: d.scope.map(resourceLabel),
    registered: d.registered,
    leaf: d.leafId === null ? null : certificateLabel(d.leafId),
    issuers: d.issuers.map(principalLabel),
    active: activeDevice(state, p) !== undefined,
    // The cascade (§17.5): an issuer of its current chain is revoked, the device itself is not.
    suspended:
      d.registered && !own && d.issuers.some((e) => revocationOf(state, d.root, e) !== undefined),
    reads: hasAbility(state, p, ABILITY.DATA_READ),
  };
}

/** The derived Control state of §79 after a record, in the corpus's vocabulary. */
export function controlState(state: ControlState): Report {
  const roots = new Set<string>([toHex(state.owner.principalId)]);
  for (const g of state.grants.values()) roots.add(toHex(g.subject));
  return {
    owner: principalLabel(state.owner.principalId),
    control_seq: num(state.seq),
    epoch: num(state.epoch.epoch),
    roles: Object.fromEntries(
      [...state.roles.entries()]
        .map(([id, role]) => [principalLabel(fromHex(id)), role] as const)
        .sort(([a], [b]) => (a < b ? -1 : 1)),
    ),
    devices: Object.fromEntries(
      [...state.devices.keys()]
        .map((id) => [principalLabel(fromHex(id)), deviceRow(state, id)] as const)
        .sort(([a], [b]) => (a < b ? -1 : 1)),
    ),
    revoked: Object.fromEntries(
      [...state.revoked.values()]
        .map(
          (r) =>
            [
              `${principalLabel(r.root)}/${principalLabel(r.device)}`,
              {
                reason: num(r.reason),
                ...(r.approval === null ? {} : { approval: { hex: toHex(r.approval) } }),
              },
            ] as const,
        )
        .sort(([a], [b]) => (a < b ? -1 : 1)),
    ),
    standing: [...roots]
      .filter((r) => !isBound(state, principalId(fromHex(r))))
      .filter((r) => rootStanding(state, principalId(fromHex(r))))
      .map((r) => principalLabel(fromHex(r)))
      .sort(),
  };
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * The reported value restricted to what the corpus states: a table keyed by
 * label (devices, queries, revoked) keeps every key, and each of its rows
 * keeps the fields the expected row lists. The corpus omits `leaf` for a
 * device bound only as an intermediate; the report gives it as null.
 */
export function asStated(expected: unknown, got: unknown): unknown {
  if (!isRecord(expected) || !isRecord(got)) return got;
  return Object.fromEntries(
    Object.entries(got).map(([k, row]) => {
      const e = expected[k];
      if (!isRecord(e) || !isRecord(row)) return [k, row];
      return [
        k,
        Object.fromEntries(
          Object.keys(row)
            .filter((f) => f in e)
            .map((f) => [f, row[f]]),
        ),
      ];
    }),
  );
}

/** Checks every field of an expected post-state against the reported one. */
export function postStateChecks(expected: Json, got: Json, prefix = "outcome/post_state"): Check[] {
  if (expected === undefined || expected === null) return [];
  return Object.keys(expected).map((k) =>
    equalCheck(`${prefix}.${k}`, expected[k], asStated(expected[k], got?.[k])),
  );
}

/** The outcome check of a validation case, then its post-state. */
function verdictChecks(c: VectorCase, report: Report): Check[] {
  const e = c.expected as Json;
  const want = e.valid === true ? "accept" : e.error.code;
  const checks = [equalCheck("outcome", want, report.outcome)];
  if (e.disposition !== undefined)
    checks.push(equalCheck("outcome/disposition", e.disposition, report.disposition));
  if (e.valid === true) checks.push(...postStateChecks(e.post_state, report.post_state));
  return checks;
}

const result = (c: VectorCase, report: Report, extra: Check[] = []): HandlerResult => ({
  checks: [...verdictChecks(c, report), ...extra],
  report,
});

// ---------------------------------------------------------------------------
// bytes: Principals, Device Certificates, transfer objects, READY

const principal: Handler = (c) => {
  const i = c.inputs as Json;
  const key = importSigningKey(hexOf(i.ed25519_seed));
  const agreement = importAgreementKey(hexOf(i.x25519_private));
  const d = principalDescriptorFromKeys(key, agreement);
  const e = c.expected as Json;
  const checks = [
    bytesCheck("ed25519_public", hexOf(e.ed25519_public), d.ed25519PublicKey),
    bytesCheck("x25519_public", hexOf(e.x25519_public), d.x25519PublicKey),
    bytesCheck("principal_id", hexOf(e.principal_id), d.principalId),
    bytesCheck("descriptor_cbor", hexOf(e.descriptor_cbor), encodePrincipalDescriptor(d)),
    check("principal_id/label", () => bytesEqual(idOf(i.label), d.principalId)),
  ];
  return {
    checks,
    report: accept([d.principalId], {
      descriptor_cbor: toHex(encodePrincipalDescriptor(d)),
      ed25519_public: toHex(d.ed25519PublicKey),
      principal_id: toHex(d.principalId),
      x25519_public: toHex(d.x25519PublicKey),
    }),
  };
};

const signedChecks = (e: Json, s: SignedObject): Check[] => [
  bytesCheck("payload_cbor", hexOf(e.payload_cbor), s.payloadBytes),
  bytesCheck("protected_header_cbor", hexOf(e.protected_header_cbor), s.protectedBytes),
  bytesCheck("signature", hexOf(e.signature), s.signature),
  bytesCheck("cose_sign1", hexOf(e.cose_sign1), s.bytes),
];

/** Bytes: the certificate signed from its inputs (§7.3); validation: parsed, then its signature. */
const deviceCertificate: Handler = (c) => {
  const i = c.inputs as Json;
  const e = c.expected as Json;
  if (c.type === "bytes") {
    const payload: DeviceCertificatePayload = {
      root: idOf(i.root),
      device: party(i.device).descriptor,
      kind: i.kind,
      mask: (decodeStrict(hexOf(i.mask_cbor)) as (number | bigint)[]).map((m) => BigInt(m)),
      scope: decodeStrict(hexOf(i.scope_cbor)) as unknown as DeviceCertificatePayload["scope"],
      serial: hexOf(i.serial),
    };
    const cert = signDeviceCertificate(payload, party(i.signer));
    return {
      checks: [
        ...signedChecks(e, cert.signed),
        bytesCheck(
          "sig_structure_cbor",
          hexOf(e.sig_structure_cbor),
          sigStructureBytes(cert.signed.protectedBytes, cert.signed.payloadBytes),
        ),
        bytesCheck("certificate_id", hexOf(e.certificate_id), cert.id),
        bytesCheck("payload_digest", hexOf(e.payload_digest), cert.payloadDigest),
      ],
      report: accept([cert.id], { payload_digest: toHex(cert.payloadDigest) }),
    };
  }
  let report: Report;
  try {
    const cert = parseDeviceCertificate(hexOf(i.cose_sign1));
    const ref = (c.context as Json).signer_descriptor as { case: string; field: string };
    const signer = decodePrincipalDescriptor(hexOf(wireCase(ref.case).expected[ref.field]));
    const v = verifySignedObject(cert.signed, signer);
    report = v.valid
      ? accept([cert.id], { payload_digest: toHex(cert.payloadDigest) })
      : refuse("INVALID_SIGNATURE", v.reason);
  } catch (err) {
    report = malformed(err);
  }
  return result(c, report);
};

/** A transfer offer or acceptance (§23), signed from its inputs. */
const signedObject: Handler = (c) => {
  const i = c.inputs as Json;
  const e = c.expected as Json;
  const resource = fromHex((wire.fixtures.resources[i.resource] as Json).id.hex);
  let payload: Uint8Array;
  if (i.object === "owner-transfer-offer-payload") {
    const head = wireCase(i.control_head).inputs.record_id;
    const nonce = sha256(utf8(`LFCP-TV-IDENTITY-OFFER-NONCE-${c.id.split("_")[0]}`)).subarray(
      0,
      16,
    );
    payload = encode(
      cborMap([
        [0, resource],
        [1, hexOf(head)],
        [2, BigInt(i.expected_next_seq)],
        [3, decodeStrict(encodePrincipalDescriptor(party(i.new_owner).descriptor))],
        [4, nonce],
      ]),
    );
  } else {
    const offer = hexOf(wireCase(i.offer).expected.cose_sign1);
    payload = encode(
      cborMap([
        [0, resource],
        [1, objectId(offer)],
        [2, idOf(i.accepting_owner)],
      ]),
    );
  }
  const signed = parseSignedObject(signObject(payload, party(i.signer)).bytes);
  const id = signed.id;
  return {
    checks: [
      bytesCheck("payload_cbor", hexOf(e.payload_cbor), payload),
      bytesCheck("protected_header_cbor", hexOf(e.protected_header_cbor), signed.protectedBytes),
      bytesCheck("signature", hexOf(e.signature), signed.signature),
      bytesCheck("cose_sign1", hexOf(e.cose_sign1), signed.bytes),
      bytesCheck("object_id", hexOf(e.object_id), id),
    ],
    report: accept([id]),
  };
};

const wireMessage: Handler = (c) => {
  const i = c.inputs as Json;
  const bytes = encodeMessage({
    type: "READY",
    messageId: hexOf(i.message_id),
    correlationId: hexOf(i.correlation),
    body: {
      wireProfile: i.wire_profile,
      serverId: hexOf(i.server_id),
      maxMessageBytes: BigInt(i.max_message_bytes),
      durability: BigInt(i.durability),
      heartbeatMs: BigInt(i.heartbeat_ms),
      extensions: [i.extension],
    },
  });
  return {
    checks: [bytesCheck("message_cbor", hexOf((c.expected as Json).message_cbor), bytes)],
    report: accept([], { message_hex: toHex(bytes) }),
  };
};

// ---------------------------------------------------------------------------
// Control Records and certificate chains

const queriesOf = (state: ControlState, labels: readonly string[]) =>
  Object.fromEntries(
    labels.map((label) => {
      const p = idOf(label);
      return [
        label,
        {
          rootOf: principalLabel(rootOf(state, p)),
          actsFor: principalLabel(actsFor(state, p)),
          bound: isBound(state, p),
          active: activeDevice(state, p) !== undefined,
        },
      ];
    }),
  );

const chainOfBody = (r: ControlRecord): CertificateChain | undefined => {
  const b = r.body as Json;
  return b.chain ?? b.deviceChain;
};

/** A Control Record on the head of its context (§62): the verdict, then the state after it. */
export function controlRecordReport(id: string): Report {
  const c = wireCase(id) as Json;
  const before = contextOf(id);
  const bytes = fromHex(c.inputs.cose_sign1.hex);
  const r = chainOrCode([...before, bytes]);
  if ("code" in r) return refuse(r.code);
  const prior = chainOrCode(before);
  const record = decodeControlRecord(bytes);
  const recordId = record.signed.id;
  const state = r.state;
  const post: Report = controlState(state);
  const type = record.body.type;
  if (type === "CAPABILITY_GRANT") {
    const g = state.grants.get(toHex(recordId));
    if (g !== undefined) post.issuer_root = principalLabel(g.issuerRoot);
  }
  const chain = chainOfBody(record);
  if (chain !== undefined) {
    const a = checkChainAuthority(chain, state.resourceId);
    if (a.valid) post.in_scope = a.inScope;
  }
  if (type === "DEVICE_REVOKE" && !("code" in prior))
    post.exposing = isExposingRevocation(prior.state, state);
  // The exact bytes of a record already in the chain: the same ACK, no transition (§47).
  if (!("code" in prior) && prior.records.some((x) => bytesEqual(x.signed.id, recordId))) {
    post.already_in_chain = true;
    post.ack_record = [...RECORD_CASES.entries()].find(
      ([rid, cid]) => rid === toHex(recordId) && cid !== id,
    )?.[1];
    post.state_unchanged =
      prior.state.seq === state.seq && bytesEqual(prior.state.head, state.head);
  }
  const queries = c.expected?.post_state?.queries;
  if (queries !== undefined) post.queries = queriesOf(state, Object.keys(queries));
  return accept([recordId], post);
}

const controlRecord: Handler = (c) => result(c, controlRecordReport(c.id));

/** verifyChain (§7.3) of the case's chain at its context head, in its Resource. */
const certificateChainCase: Handler = (c) => {
  const i = c.inputs as Json;
  const context = chainOrCode(contextOf(c.id));
  if ("code" in context) throw new Error(`the context of ${c.id} is ${context.code}`);
  const state = context.state;
  const root = idOf(i.root);
  let report: Report;
  let chain: CertificateChain;
  try {
    chain = certificateChainFromCbor(
      (i.chain as { hex: string }[]).map((b) => fromHex(b.hex)),
      root,
    );
  } catch (err) {
    return result(c, malformed(err));
  }
  const v = verifyChain(
    chain,
    root,
    state.principals.get(toHex(root)),
    state.resourceId,
    deviceChainChecks(state),
  );
  if (!v.valid) report = refuse(v.wireCode, `${v.rule}: ${v.reason}`);
  else
    report = accept(
      chain.certificates.map((x) => x.id),
      {
        leaf: principalLabel(v.leaf.device.principalId),
        leaf_certificate: certificateLabel(v.leafId),
        kind: v.leaf.kind,
        mask: v.leaf.mask.map(num),
        issuers: v.issuers.map(principalLabel),
        in_scope: v.inScope,
        new_bindings: v.bindings
          .map((b) => b.device.principalId)
          .filter((p) => !isBound(state, p))
          .map(principalLabel),
      },
    );
  return result(c, report);
};

// ---------------------------------------------------------------------------
// Data Plane objects

const utf8 = (s: string) => new TextEncoder().encode(s);
/** fixtures.derivations.dek: SHA-256('LFCP-TV-IDENTITY-DEK-' || resource || '-EPOCH-' || epoch). */
const dekOf = (resource: string, epoch: bigint) =>
  importResourceDEK(sha256(utf8(`LFCP-TV-IDENTITY-DEK-${resource}-EPOCH-${epoch}`)));

const RAW = { encode: (b: Uint8Array) => b, decode: (b: Uint8Array) => b };

/** A unit the receiver accepted before this one: its previous unit, or its equivocation partner. */
async function seenFor(c: VectorCase) {
  const seen = new InMemorySeenUnits();
  const i = c.inputs as Json;
  const before: string[] = [];
  if (typeof i.previous === "string") before.push(i.previous);
  const acceptedUnit = (c.context as Json)?.accepted_unit;
  if (acceptedUnit?.case !== undefined) before.push(acceptedUnit.case);
  for (const name of before) {
    const bytes = fromHex(wireCase(name).inputs.cose_sign1.hex);
    const p = parseDataUnit(bytes).payload;
    const id = objectId(bytes);
    await seen.recordSignatureValid(p.resourceId, p.actor, p.actorSeq, id as never);
    await seen.markAccepted(p.resourceId, p.actor, p.actorSeq, id as never);
  }
  return seen;
}

/** §26.3, §19.1: a Data Unit on the receiver's latest state, then its plaintext. */
export async function dataUnitReport(c: VectorCase): Promise<Report> {
  const view = latestChain(c);
  const bytes = fromHex((c.inputs as Json).cose_sign1.hex);
  const seen = await seenFor(c);
  const v = await checkDataUnit(view, bytes, seen);
  if (v.kind === "rejected") return refuse(v.wireCode, `${v.reason}: ${v.message}`);
  if (v.kind === "equivocation") return refuse(v.wireCode, "two units for one actor sequence");
  if (v.kind === "quarantined") return refuse(v.code, v.reason, { disposition: "quarantine" });
  const p = v.parsed.payload;
  const resource = resourceLabel(p.resourceId);
  const received = await receiveDataUnit(view, bytes, {
    seen: await seenFor(c),
    dek: (epoch) => dekOf(resource, epoch),
    profile: { dataProfile: view.state.dataProfile, ...RAW },
  });
  return accept(
    [v.unitId],
    received.kind === "accepted" ? { plaintext_hex: toHex(received.value) } : {},
  );
}

const dataUnit: Handler = async (c) => result(c, await dataUnitReport(c));

/** The facts a Key Package case names (holds_<P>_<code>, direct_<P>_<code>, invitation_exception_<P>). */
function packageFacts(state: ControlState, names: readonly string[]): Report {
  // §80.1: an unbound Principal's abilities are its direct ones (owner, or an active grant).
  const direct = (p: PrincipalId, code: bigint) => !isBound(state, p) && hasAbility(state, p, code);
  const out: Report = {};
  for (const name of names) {
    let m = /^holds_(.+)_(\d+)$/.exec(name);
    if (m !== null) {
      out[name] = hasAbility(state, idOf(m[1] as string), BigInt(m[2] as string));
      continue;
    }
    m = /^direct_(.+)_(\d+)$/.exec(name);
    if (m !== null) {
      out[name] = direct(idOf(m[1] as string), BigInt(m[2] as string));
      continue;
    }
    m = /^invitation_exception_(.+)$/.exec(name);
    if (m !== null) {
      const p = idOf(m[1] as string);
      // §25.2: the recipient holds no data/read and an active invite grant.
      out[name] =
        !hasAbility(state, p, ABILITY.DATA_READ) && hasAbility(state, p, ABILITY.INVITE_CLAIM);
    }
  }
  return out;
}

/** §25.2: a Key Package on the receiver's latest state. */
export function keyPackageReport(c: VectorCase): Report {
  const view = latestChain(c);
  let parsed: ReturnType<typeof parseKeyPackage>;
  try {
    parsed = parseKeyPackage(fromHex((c.inputs as Json).cose_sign1.hex));
  } catch (err) {
    return malformed(err);
  }
  const v = verifyKeyPackage(view, parsed);
  if (v.kind === "rejected") return refuse(v.wireCode, `${v.reason}: ${v.message}`);
  const names = Object.keys((c.expected as Json).post_state ?? {});
  const at = view.stateAt(parsed.payload.controlHead) as ControlState;
  return accept([parsed.signed.id], packageFacts(at, names));
}

const keyPackage: Handler = (c) => result(c, keyPackageReport(c));

/** §25.2, §80.1 for every (sender, recipient) at each head; an undescribed sender is MISSING_DEPENDENCY. */
const keyPackageMatrix: Handler = (c) => {
  const i = c.inputs as Json;
  const table: Record<string, Record<string, Record<string, string>>> = {};
  for (const [name, head] of Object.entries(i.heads as Record<string, string>)) {
    const state = (chainOrCode(recordsAt(head)) as Linear).state;
    table[name] = {};
    for (const s of i.principals as string[]) {
      const row: Record<string, string> = {};
      for (const r of i.principals as string[]) {
        const sender = idOf(s);
        row[r] = !state.principals.has(toHex(sender))
          ? "MISSING_DEPENDENCY"
          : canDistributeKey(state, sender, idOf(r), 0n as never).allowed
            ? "accept"
            : "AUTHORIZATION_FAILED";
      }
      (table[name] as Record<string, Record<string, string>>)[s] = row;
    }
  }
  return {
    checks: [
      equalCheck(
        "outcome_by_head_sender_recipient",
        (c.expected as Json).outcome_by_head_sender_recipient,
        table,
      ),
    ],
    report: accept([], table),
  };
};

const snapshot: Handler = (c) => {
  const view = latestChain(c);
  const v = checkSnapshot(view, fromHex((c.inputs as Json).cose_sign1.hex));
  return result(c, v.kind === "valid" ? accept([v.snapshotId]) : refuse(v.wireCode, `${v.reason}`));
};

/** W §41: the requests a revoked reader's session is refused. */
const REFUSED_READS = [
  "later Control Records",
  "DATA_HAVE",
  "DATA_GET",
  "KEY_PACKAGE_GET",
  "SNAPSHOT_GET",
  "presence",
];

/** W §41, §80.1: a read by a session at the accepted head; the revoked-reader prefix for Control reads. */
export function sessionReadReport(c: VectorCase): Report {
  const i = c.inputs as Json;
  const chain = latestChain(c);
  const session = idOf(i.session);
  const identity = (i.server_extensions as string[]).includes("identity-01");
  if (hasAbility(chain.state, session, ABILITY.DATA_READ))
    return accept([chain.state.head], {
      read: "full",
      control_head: recordLabel(chain.state.head),
    });
  const control = i.request === "RESOURCE_OPEN" || i.request.startsWith("CONTROL_");
  const prefix = identity && control ? revokedReaderPrefix(chain, session) : undefined;
  if (prefix === undefined)
    return refuse("AUTHORIZATION_FAILED", "no data/read and no revoked-reader prefix");
  return accept([prefix.recordId], {
    read: "prefix",
    control_head: recordLabel(prefix.recordId),
    records: chain.records.slice(0, prefix.index + 1).map((r) => recordLabel(r.signed.id)),
    refused_reads: REFUSED_READS,
  });
}

const sessionRead: Handler = (c) => result(c, sessionReadReport(c));

/** W §41: uploads are not reads; the object is checked as from its author. */
const sessionUpload: Handler = async (c) => {
  const request = (c.inputs as Json).request;
  if (request === "DATA_PUT") return result(c, await dataUnitReport(c));
  if (request === "KEY_PACKAGE_PUT") return result(c, keyPackageReport(c));
  throw new Error(`unknown upload ${request}`);
};

/** IDENTITY-PROFILE-01 §8.1 on concrete heads. */
const rotatorTestCase: Handler = (c) => {
  const heads = (c.inputs as Json).heads as Record<string, string>;
  const expected = (c.expected as Json).tables as Record<
    string,
    { candidates: Record<string, unknown> }
  >;
  const tables: Record<string, unknown> = {};
  for (const [name, e] of Object.entries(expected)) {
    const head = heads[name.split(" ")[0] as string] as string;
    const state = (chainOrCode(recordsAt(head)) as Linear).state;
    tables[name] = {
      readers: sortedLabels(readersAt(state).map((r) => r.principalId)),
      candidates: Object.fromEntries(
        Object.keys(e.candidates).map((label) => {
          const t = rotatorTest(state, idOf(label));
          return [
            label,
            {
              holds_6: t.holds6,
              holds_7: t.holds7,
              every_reader_of_own_root: t.everyReaderOfOwnRoot,
              rotator: t.rotator,
            },
          ];
        }),
      ),
    };
  }
  return {
    checks: [equalCheck("tables", expected, tables)],
    report: accept([], tables),
  };
};

export const IDENTITY_WIRE_HANDLERS: Readonly<Record<string, Handler>> = {
  "bytes/principal": principal,
  "bytes/device_certificate": deviceCertificate,
  "validation/device_certificate": deviceCertificate,
  "bytes/signed_object": signedObject,
  "bytes/wire_message": wireMessage,
  "validation/control_record": controlRecord,
  "validation/certificate_chain": certificateChainCase,
  "validation/data_unit": dataUnit,
  "validation/key_package": keyPackage,
  "behavioral/key_package_matrix": keyPackageMatrix,
  "validation/snapshot": snapshot,
  "validation/session_read": sessionRead,
  "validation/session_upload": sessionUpload,
  "behavioral/rotator_test": rotatorTestCase,
};
