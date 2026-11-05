// Typed access to the identity corpora (wire identity vectors, flow
// fixtures) at the baseline pinned in spec.lock, for the identity flow tests
// (LFCP-04-410).
import { fromHex, type PrincipalId, principalId } from "@openlfcp/core";
import {
  type AgreementKeyPair,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  sha256,
} from "@openlfcp/crypto";
import {
  type CertificateChain,
  type ChainResult,
  certificateChain,
  type DeviceCertificate,
  parseDeviceCertificate,
  principalDescriptorFromKeys,
  type Signer,
  validateControlChain,
} from "@openlfcp/wire";
import { openSpec } from "../spec.mjs";

export type Linear = Extract<ChainResult, { kind: "linear" }>;
interface Hex {
  readonly hex: string;
}
interface Ref {
  readonly case: string;
  readonly field: string;
  readonly in: "inputs" | "expected";
}
export interface WireCase {
  readonly id: string;
  readonly kind: string;
  // biome-ignore lint/suspicious/noExplicitAny: corpus JSON
  readonly inputs: any;
  readonly context?: { readonly records: readonly Ref[] };
  // biome-ignore lint/suspicious/noExplicitAny: corpus JSON
  readonly expected: any;
}
interface CertificateFixture {
  readonly root: string;
  readonly device: string;
  readonly issuer: string;
  readonly cose_sign1: Hex;
  readonly payload_cbor: Hex;
  readonly certificate_id: Hex;
  readonly payload_digest: Hex;
}
interface WireCorpus {
  readonly fixtures: {
    readonly certificates: Readonly<Record<string, CertificateFixture>>;
    readonly resources: Readonly<
      Record<string, { readonly id: Hex } & Record<string, Hex | string>>
    >;
    // biome-ignore lint/suspicious/noExplicitAny: corpus JSON
    readonly record_sets: Readonly<Record<string, any>>;
  };
  readonly cases: readonly WireCase[];
}
export interface FlowStep {
  readonly n: number;
  readonly action: string;
  readonly case?: string;
  readonly bytes_of?: string;
  readonly aside?: boolean;
  readonly branch?: string;
  // biome-ignore lint/suspicious/noExplicitAny: corpus JSON
  readonly phase_input?: any;
  // biome-ignore lint/suspicious/noExplicitAny: corpus JSON
  readonly [k: string]: any;
}
export interface FlowCase {
  readonly id: string;
  readonly inputs: { readonly mode: string; readonly steps: readonly FlowStep[] };
  // biome-ignore lint/suspicious/noExplicitAny: corpus JSON
  readonly expected: { readonly steps: readonly any[] };
}

export const WIRE_IDENTITY = "test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json";
export const FLOW_FIXTURES = "test-vectors/identity-01/IDENTITY-FLOW-FIXTURES-01.json";

const spec = openSpec();
export const wire = spec.readJson(WIRE_IDENTITY) as WireCorpus;
export const flows = (spec.readJson(FLOW_FIXTURES) as { cases: readonly FlowCase[] }).cases;

const byId = new Map(wire.cases.map((c) => [c.id, c]));
export function wireCase(id: string): WireCase {
  const c = byId.get(id.replace(/^wire:/, ""));
  if (c === undefined) throw new Error(`no wire case ${id}`);
  return c;
}
export const flow = (id: string): FlowCase => {
  const f = flows.find((x) => x.id === id);
  if (f === undefined) throw new Error(`no flow ${id}`);
  return f;
};
export const expectedStep = (f: FlowCase, n: number) =>
  f.expected.steps.find((s) => s.n === n) ?? {};

export function bytesOfRef(ref: Ref): Uint8Array {
  const c = wireCase(ref.case);
  const v = c[ref.in][ref.field] as Hex | undefined;
  if (v === undefined) throw new Error(`no ${ref.in}.${ref.field} in ${ref.case}`);
  return fromHex(v.hex);
}

/** The record bytes of a control_record case. */
export const recordOf = (id: string): Uint8Array => fromHex(wireCase(id).inputs.cose_sign1.hex);

/** The chain a case was decided on: its context records, a record set, the records after it. */
export function contextOf(id: string): Uint8Array[] {
  const ctx = wireCase(id).context as
    | { records?: readonly Ref[]; record_set?: string; records_after_set?: readonly Ref[] }
    | undefined;
  const set =
    ctx?.record_set === undefined
      ? []
      : (wire.fixtures.record_sets[ctx.record_set].records as Hex[]).map((r) => fromHex(r.hex));
  return [
    ...(ctx?.records ?? []).map(bytesOfRef),
    ...set,
    ...(ctx?.records_after_set ?? []).map(bytesOfRef),
  ];
}

/** The chain after an accepted control_record case: its context and its own record. */
export function recordsAt(id: string): Uint8Array[] {
  const c = wireCase(id);
  const own = c.inputs?.cose_sign1?.hex;
  return own === undefined ? contextOf(id) : [...contextOf(id), fromHex(own)];
}

export function chainOf(records: readonly Uint8Array[]): Linear {
  const c = validateControlChain([...records]);
  if (c.kind !== "linear") throw new Error(`the chain is ${c.kind}`);
  return c;
}
export const chainAt = (id: string): Linear => chainOf(recordsAt(id));

const parties = new Map<string, Signer & { agreement: AgreementKeyPair }>();
const utf8 = (s: string) => new TextEncoder().encode(s);
/** A fixture Principal: h('LFCP-TV-' + label + '-ED25519') (§12.1). */
export function party(label: string): Signer & { agreement: AgreementKeyPair } {
  let p = parties.get(label);
  if (p === undefined) {
    const key = importSigningKey(sha256(utf8(`LFCP-TV-${label}-ED25519`)));
    const agreement = importAgreementKey(sha256(utf8(`LFCP-TV-${label}-X25519`)));
    p = { key, descriptor: principalDescriptorFromKeys(key, agreement), agreement };
    parties.set(label, p);
  }
  return p;
}
export const idOf = (label: string): PrincipalId =>
  principalId(party(label).descriptor.principalId);

export const certFixture = (label: string): CertificateFixture => {
  const c = wire.fixtures.certificates[label];
  if (c === undefined) throw new Error(`no certificate ${label}`);
  return c;
};
export const cert = (label: string): DeviceCertificate =>
  parseDeviceCertificate(fromHex(certFixture(label).cose_sign1.hex));

/** The issuing chain of a fixture certificate, through the issuers' own fixture certificates. */
export function chainOfCert(label: string): CertificateChain {
  const certs: DeviceCertificate[] = [];
  let at: CertificateFixture | undefined = certFixture(label);
  certs.push(cert(label));
  while (at !== undefined && at.issuer !== at.root) {
    const issuer = Object.entries(wire.fixtures.certificates).find(
      ([, c]) => c.device === at?.issuer,
    );
    if (issuer === undefined) throw new Error(`no certificate for issuer ${at.issuer}`);
    certs.push(cert(issuer[0]));
    at = issuer[1];
  }
  return certificateChain(certs, idOf(certFixture(label).root));
}

export const resourceOf = (name: string) =>
  fromHex((wire.fixtures.resources[name] as { id: Hex }).id.hex);

/** The DEK of epoch 0 of a fixture Resource (`dek0`). */
export const dek0Of = (name: string) =>
  importResourceDEK(fromHex((wire.fixtures.resources[name] as unknown as { dek0: Hex }).dek0.hex));
