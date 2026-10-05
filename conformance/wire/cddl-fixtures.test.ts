// wire/fixtures/manifest.json at the pinned spec commit (LFCP-017): each
// CDDL fixture names a rule, a CBOR item (a published vector field or a
// hand-built diagnostic-notation file) and whether it must pass or fail.
//
// For a rule sdk-ts decodes, a must-fail item must be rejected and a
// published positive must be accepted. Items taken from the inputs of
// validation cases are CDDL-valid by design; their real outcome is asserted
// by the vector run, not here. Rules sdk-ts cannot decode yet are listed
// in cddl-pending.json; a rule in neither place fails the run.

import { bytesEqual, fromHex } from "@openlfcp/core";
import {
  canonicalFrontierFromCbor,
  controlBodyFromCbor,
  decodeControlRecord,
  decodeControlRecordPayload,
  decodeDataUnitPayload,
  decodeKeyPackagePayload,
  decodePrincipalDescriptor,
  decodeSnapshotPayload,
  ownerTransferAcceptPayloadFromCbor,
  ownerTransferOfferPayloadFromCbor,
  parseDataUnit,
  parseKeyPackage,
  parseOwnerTransferAccept,
  parseOwnerTransferOffer,
  parseSignedObject,
  parseSnapshot,
  sigStructureBytes,
} from "@openlfcp/wire";
import { type CborValue, cborMap, decodeDeterministic, encode } from "@openlfcp/wire/cbor";
import { describe, expect, it } from "vitest";
import { describeError } from "../checks.js";
import { parseDiag } from "../diag.js";
import type { VectorSuite } from "../runner.js";
import { log, openSpec } from "../spec.mjs";
import cddlPending from "./cddl-pending.json" with { type: "json" };

interface Fixture {
  readonly rule: string;
  readonly expect: "pass" | "fail";
  readonly note?: string;
  readonly source: {
    readonly case?: string;
    readonly field?: string;
    readonly from?: "inputs" | "expected";
    readonly prefix_hex?: string;
    readonly diag?: string;
  };
}

/** Decoders for the rules sdk-ts implements: each throws when the item is rejected. */
const RULES: Readonly<Record<string, (bytes: Uint8Array) => unknown>> = {
  "principal-descriptor": decodePrincipalDescriptor,
  // The item is used as the protected header of an otherwise valid object.
  "lfcp-protected-header": (b) =>
    parseSignedObject(encode([b, cborMap([]), Uint8Array.of(0xa0), new Uint8Array(64)])),
  "control-record-payload": decodeControlRecordPayload,
  // typed-control-record-payload admits only the core types 0-8 (§14 also allows
  // extensions 32+, which this decoder keeps; queued as spec gap G2).
  "typed-control-record-payload": (b) => {
    const p = decodeControlRecordPayload(b);
    if (p.controlType > 8n) throw new Error("not a core Control Record type");
    controlBodyFromCbor(p.controlType, p.body);
  },
  "genesis-record-payload": (b) => {
    const p = decodeControlRecordPayload(b);
    if (p.controlType !== 0n) throw new Error("not a Genesis record");
    controlBodyFromCbor(p.controlType, p.body);
  },
  "control-record": decodeControlRecord,
  "owner-transfer-offer-payload": (b) => ownerTransferOfferPayloadFromCbor(decodeDeterministic(b)),
  "owner-transfer-offer": parseOwnerTransferOffer,
  "owner-transfer-accept-payload": (b) =>
    ownerTransferAcceptPayloadFromCbor(decodeDeterministic(b)),
  "owner-transfer-accept": parseOwnerTransferAccept,
  "sig-structure": (b) => {
    const v = decodeDeterministic(b) as CborValue[];
    const [label, prot, aad, payload] = v;
    if (!Array.isArray(v) || v.length !== 4 || label !== "Signature1")
      throw new Error('not ["Signature1", protected, external_aad, payload]');
    if (!(prot instanceof Uint8Array) || !(payload instanceof Uint8Array))
      throw new Error("protected and payload must be byte strings");
    if (!(aad instanceof Uint8Array) || aad.length !== 0)
      throw new Error("external_aad must be h''");
    if (!bytesEqual(sigStructureBytes(prot, payload), b)) throw new Error("not the §10.5 encoding");
  },
  "key-package-payload": decodeKeyPackagePayload,
  "key-package": parseKeyPackage,
  "data-unit-payload": decodeDataUnitPayload,
  "data-unit": parseDataUnit,
  "canonical-frontier": (b) => canonicalFrontierFromCbor(decodeDeterministic(b)),
  "snapshot-payload": decodeSnapshotPayload,
  snapshot: parseSnapshot,
};
const PENDING: Readonly<Record<string, string>> = cddlPending.rules;

const spec = openSpec();
const manifest = spec.readJson("wire/fixtures/manifest.json") as { fixtures: Fixture[] };
const suite = spec.readJson("test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json") as VectorSuite;

function item(f: Fixture): Uint8Array {
  const s = f.source;
  if (s.diag !== undefined) return encode(parseDiag(spec.readText(`wire/fixtures/${s.diag}`)));
  const c = suite.cases.find((x) => x.id === s.case);
  const where = (s.from === "inputs" ? c?.inputs : c?.expected) as
    | Record<string, { hex?: string }>
    | undefined;
  const hex = s.field === undefined ? undefined : where?.[s.field]?.hex;
  if (hex === undefined)
    throw new Error(`no hex value ${s.case}.${s.from ?? "expected"}.${s.field}`);
  return fromHex(`${s.prefix_hex ?? ""}${hex}`);
}

const label = (f: Fixture) =>
  `${f.expect} ${f.rule} <- ${
    f.source.diag ?? `${f.source.case}.${f.source.from ?? "expected"}.${f.source.field}`
  }${f.source.prefix_hex ? ` (prefix ${f.source.prefix_hex})` : ""}`;

log(
  `LFCP CDDL fixtures: wire/fixtures/manifest.json from ${spec.lock.repository} ` +
    `${spec.lock.tag} (${spec.lock.commit}), ${manifest.fixtures.length} fixtures`,
);

describe(`CDDL fixture manifest at ${spec.lock.tag}`, () => {
  for (const f of manifest.fixtures) {
    const run = Object.hasOwn(RULES, f.rule) ? RULES[f.rule] : undefined;
    if (run === undefined) {
      if (Object.hasOwn(PENDING, f.rule)) it.todo(`${label(f)}: pending -> ${PENDING[f.rule]}`);
      else
        it(`${label(f)}: unclassified rule`, () => {
          throw new Error(`rule ${f.rule} has no decoder and is not in cddl-pending.json`);
        });
    } else if (f.expect === "pass" && f.source.from === "inputs") {
      it.todo(`${label(f)}: validation input, outcome asserted by the vector run`);
    } else {
      it(label(f), () => {
        let error: unknown = null;
        try {
          run(item(f));
        } catch (e) {
          error = e;
        }
        if (f.expect === "fail") expect(error, "must be rejected, but was accepted").not.toBeNull();
        else expect(error === null ? null : describeError(error)).toBeNull();
      });
    }
  }

  it("lists no pending rule that sdk-ts now decodes", () => {
    expect(Object.keys(PENDING).filter((r) => Object.hasOwn(RULES, r))).toEqual([]);
  });
});
