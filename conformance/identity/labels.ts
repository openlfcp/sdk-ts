// Fixture labels for an identity outcome export (LFCP-04-412): the corpus
// names Principals, certificates and Resources by label, and so does the
// export, so that two SDKs' outcomes compare without either reading the
// other. The tables are built from the corpus inputs and fixtures only
// (principal cases, the derivation rule of fixtures.derivations, the
// certificate labels the inputs give next to their bytes), never from an
// expected value.
import { fromHex, toHex } from "@openlfcp/core";
import { type CertificateChain, decodeControlRecord, objectId } from "@openlfcp/wire";
import { idOf, wire } from "./corpus.js";

// biome-ignore lint/suspicious/noExplicitAny: corpus JSON
type Json = any;

const numbered = (prefix: string, n: number, width: number) =>
  Array.from({ length: n }, (_, i) => `${prefix}${String(i + 1).padStart(width, "0")}`);

/** fixtures.derivations.limit_principals: Principals derived from these labels. */
const DERIVED = [
  ...numbered("LIMIT_BOB_", 30, 2),
  ...numbered("LIMIT_OWNER_", 30, 2),
  ...numbered("PAIR_S_", 40, 2),
  ...numbered("TOMB_X_", 65, 3),
  ...numbered("TOMB_I_", 64, 3),
];

function principalLabels(): Map<string, string> {
  const labels = new Set<string>();
  for (const c of wire.cases as readonly Json[]) {
    if (c.kind === "principal") labels.add(c.inputs.label);
    for (const k of ["signer", "issuer", "actor", "sender", "recipient", "publisher", "session"])
      if (typeof c.inputs?.[k] === "string") labels.add(c.inputs[k]);
    if (c.kind === "device_certificate" && typeof c.inputs.device === "string")
      labels.add(c.inputs.device);
    for (const p of c.inputs?.principals ?? []) labels.add(p);
  }
  for (const f of Object.values(wire.fixtures.certificates) as Json[]) {
    labels.add(f.root);
    labels.add(f.device);
    labels.add(f.issuer);
  }
  for (const l of DERIVED) labels.add(l);
  const out = new Map<string, string>();
  for (const l of [...labels].sort()) {
    // Labels that name no derivable Principal (prose, "X epoch 0") are skipped.
    if (!/^[A-Z][A-Z0-9_']*$/.test(l)) continue;
    const id = toHex(idOf(l));
    if (!out.has(id)) out.set(id, l);
  }
  return out;
}

/** Certificate labels by certificate ID hex, from every input that names certificates next to their bytes. */
function certificateLabels(): Map<string, string> {
  const out = new Map<string, string>();
  const put = (bytes: Uint8Array, label: unknown) => {
    if (typeof label === "string") out.set(toHex(objectId(bytes)), label);
  };
  for (const [label, f] of Object.entries(wire.fixtures.certificates) as [string, Json][])
    put(fromHex(f.cose_sign1.hex), label);
  for (const c of wire.cases as readonly Json[]) {
    if (c.kind === "device_certificate" && c.expected?.cose_sign1 !== undefined)
      put(fromHex(c.expected.cose_sign1.hex), c.inputs.certificate);
    if (c.kind === "certificate_chain" && Array.isArray(c.inputs.certificates))
      (c.inputs.chain as { hex: string }[]).forEach((b, i) => {
        put(fromHex(b.hex), c.inputs.certificates[i]);
      });
    // A DEVICE_GRANT, Genesis or commit names its chain's certificates in its input body.
    const names = c.inputs?.body?.chain ?? c.inputs?.body?.device_chain;
    if (c.kind === "control_record" && Array.isArray(names) && c.inputs.cose_sign1 !== undefined) {
      let chain: CertificateChain | undefined;
      try {
        const { body } = decodeControlRecord(fromHex(c.inputs.cose_sign1.hex));
        chain = "chain" in body ? body.chain : "deviceChain" in body ? body.deviceChain : undefined;
      } catch {
        // A malformed record names no certificate.
      }
      chain?.certificates.forEach((cert, i) => {
        if (!out.has(toHex(cert.id))) put(cert.signed.bytes, names[i]);
      });
    }
  }
  return out;
}

const PRINCIPALS = principalLabels();
const CERTIFICATES = certificateLabels();
const RESOURCES = new Map(
  Object.entries(wire.fixtures.resources as Record<string, { id: { hex: string } }>).map(
    ([name, r]) => [r.id.hex, name],
  ),
);

/** A Principal's label, or its hex when the corpus names it nowhere. */
export const principalLabel = (id: Uint8Array): string => PRINCIPALS.get(toHex(id)) ?? toHex(id);
/** A certificate's label by its ID, or the ID's hex. */
export const certificateLabel = (id: Uint8Array): string =>
  CERTIFICATES.get(toHex(id)) ?? toHex(id);
/** A Resource's fixture name, or its hex. */
export const resourceLabel = (id: Uint8Array): string => RESOURCES.get(toHex(id)) ?? toHex(id);
