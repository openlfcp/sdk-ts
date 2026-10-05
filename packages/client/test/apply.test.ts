import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { InMemoryActorSequenceReservation, InMemoryLfcpStorage } from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  type DataProfileCodec,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { createDataUnit, type DataProfileHandler, DataUnitApplier } from "../src/index.js";

// The profile-agnostic applier with an opaque text profile. The Shared
// Objects profile end to end is conformance/shared-objects/data-unit-apply.test.ts.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const R = resourceId(bytes32(200));
const PROFILE = "org.example.text.v1";
const DEK0 = importResourceDEK(bytes32(90));

const records: Uint8Array[] = [];
let head: ControlRecordId | null = null;
function add(body: ControlBody) {
  const s = signControlRecord(
    { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head },
    body,
    OWNER,
  );
  records.push(s.bytes);
  head = s.recordId;
}
add({
  type: "GENESIS",
  dataProfile: PROFILE,
  owner: OWNER.descriptor,
  dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
  endpoints: [{ url: "wss://a.example.test", priority: 0n }],
  coordinatorUrl: "wss://a.example.test",
});
const chain = validateControlChain(records);
if (chain.kind !== "linear") throw new Error(chain.kind);
const VIEW: Extract<ChainResult, { kind: "linear" }> = chain;

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (plaintext) => String.fromCharCode(...plaintext),
};

/** A text profile that keeps merged values and refuses "boom". */
function textHandler(merged: string[]): DataProfileHandler<string> {
  return {
    dataProfile: PROFILE,
    codecFor: () => TEXT,
    apply: (unit, value) => {
      if (value === "boom") throw Object.assign(new Error("refused"), { code: "TEXT_REFUSED" });
      merged.push(value);
      return { merged: [unit.unitId], objects: [], diagnostics: [] };
    },
    exclude: () => ({ objects: [], pending: [] }),
  };
}

async function units(...values: string[]) {
  const sequences = new InMemoryActorSequenceReservation();
  const out: { bytes: Uint8Array; unitId: DataUnitId }[] = [];
  for (const value of values)
    out.push(
      await createDataUnit({
        view: VIEW,
        controlHead: VIEW.state.head,
        actor: OWNER,
        dek: DEK0,
        sequences,
        previousUnitId: out.at(-1)?.unitId ?? null,
        profile: TEXT,
        value,
      }),
    );
  return out;
}

describe("DataUnitApplier (profile-agnostic)", () => {
  it("dispatches accepted units to the Resource's profile once, and replays are duplicates", async () => {
    const merged: string[] = [];
    const storage = new InMemoryLfcpStorage();
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [textHandler(merged) as DataProfileHandler<unknown>],
    });
    const [u1, u2] = await units("one", "two");
    expect(await applier.receive(VIEW, (u1 as { bytes: Uint8Array }).bytes)).toMatchObject({
      kind: "applied",
      dataProfile: PROFILE,
      haveEligible: false,
    });
    expect(await applier.receive(VIEW, (u2 as { bytes: Uint8Array }).bytes)).toMatchObject({
      kind: "applied",
    });
    expect(await applier.receive(VIEW, (u1 as { bytes: Uint8Array }).bytes)).toMatchObject({
      kind: "duplicate",
    });
    expect(merged).toEqual(["one", "two"]);
  });

  it("reports a profile refusal as profile-rejected and keeps the exact unit", async () => {
    const merged: string[] = [];
    const storage = new InMemoryLfcpStorage();
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [textHandler(merged) as DataProfileHandler<unknown>],
    });
    const [u] = await units("boom");
    const unit = u as { bytes: Uint8Array; unitId: DataUnitId };
    expect(await applier.receive(VIEW, unit.bytes)).toMatchObject({
      kind: "profile-rejected",
      code: "TEXT_REFUSED",
    });
    const kept = await storage.dataUnits.get(unit.unitId);
    expect([kept?.status, toHex(kept?.bytes ?? new Uint8Array())]).toEqual([
      "profile-rejected",
      toHex(unit.bytes),
    ]);
    expect(merged).toEqual([]);
  });

  it("verifies a unit of an unsupported profile without a DEK", async () => {
    let deks = 0;
    const storage = new InMemoryLfcpStorage();
    const applier = new DataUnitApplier({
      storage,
      dek: () => {
        deks++;
        return DEK0;
      },
      handlers: [],
    });
    const [u] = await units("opaque");
    expect(await applier.receive(VIEW, (u as { bytes: Uint8Array }).bytes)).toMatchObject({
      kind: "profile-unsupported",
      code: "PROFILE_UNSUPPORTED",
    });
    expect(deks).toBe(0);
  });
});
