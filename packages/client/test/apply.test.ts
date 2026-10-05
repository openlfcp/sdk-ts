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
  rotateEpoch,
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

describe("DataUnitApplier: stale work re-applied after a cutoff (§19.1, §26.2, G-EP5, G-DP1-GAP)", () => {
  // OWNER writes 1, 2, 3 in epoch 0; a Key Epoch closes epoch 0 at OWNER 2,
  // so 3 is stale; the re-applied work is 4 in epoch 1, naming 2.
  const DEK1 = importResourceDEK(bytes32(91));
  const rotation = rotateEpoch(VIEW.state, OWNER, {
    reason: 0n,
    finalFrontier: [{ principalId: OWNER.descriptor.principalId, contiguous: 2n, extras: [] }],
    dek: DEK1,
  });
  const rotated = validateControlChain([...records, rotation.bytes]);
  if (rotated.kind !== "linear") throw new Error(rotated.kind);
  const ROTATED = rotated;
  const deks = (e: bigint) => (e === 0n ? DEK0 : DEK1);
  const build = async () => {
    const [u1, u2, u3] = (await units("one", "two", "three")) as {
      bytes: Uint8Array;
      unitId: DataUnitId;
    }[];
    const sequences = new InMemoryActorSequenceReservation();
    for (let i = 0; i < 3; i++)
      await sequences.reserveNext(VIEW.state.resourceId, OWNER.descriptor.principalId);
    const u4 = await createDataUnit({
      view: ROTATED,
      controlHead: ROTATED.state.head,
      actor: OWNER,
      dek: DEK1,
      sequences,
      previousUnitId: (u2 as { unitId: DataUnitId }).unitId,
      profile: TEXT,
      value: "four",
    });
    expect(u4.seq).toBe(4n);
    return { u1, u2, u3, u4 } as Record<"u1" | "u2" | "u3" | "u4", { bytes: Uint8Array }>;
  };
  const applier = (merged: string[]) =>
    new DataUnitApplier({
      storage: new InMemoryLfcpStorage(),
      dek: deks,
      handlers: [textHandler(merged) as DataProfileHandler<unknown>],
    });

  it("a receiver that knows the cutoff quarantines 3 and links the re-applied 4 across it", async () => {
    const merged: string[] = [];
    const a = applier(merged);
    const { u1, u2, u3, u4 } = await build();
    for (const u of [u1, u2]) await a.receive(ROTATED, u.bytes);
    expect(await a.receive(ROTATED, u3.bytes)).toMatchObject({ kind: "quarantined" });
    expect(await a.receive(ROTATED, u4.bytes)).toMatchObject({ kind: "applied" });
    expect(merged).toEqual(["one", "two", "four"]);
  });

  it("a receiver that merged 3 before the cutoff holds 4 until reconciling excludes 3", async () => {
    const merged: string[] = [];
    const a = applier(merged);
    const { u1, u2, u3, u4 } = await build();
    for (const u of [u1, u2, u3]) await a.receive(VIEW, u.bytes);
    expect(await a.receive(ROTATED, u4.bytes)).toMatchObject({
      kind: "held",
      reason: "PREV_MISMATCH",
    });
    const r = await a.reconcileEpochs(ROTATED);
    expect(r.excluded).toHaveLength(1);
    expect(r.released.map((x) => x.kind)).toEqual(["applied"]);
    expect(merged).toEqual(["one", "two", "three", "four"]);
  });
});

describe("DataUnitApplier (profile-agnostic)", () => {
  it("releases a unit held across an abandoned sequence once its previous unit is accepted (§26.2, G-DP1-GAP)", async () => {
    const merged: string[] = [];
    const storage = new InMemoryLfcpStorage();
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [textHandler(merged) as DataProfileHandler<unknown>],
    });
    // The writer abandons sequence 3, so sequence 4 links to 2.
    const sequences = new InMemoryActorSequenceReservation();
    const make = (value: string, previousUnitId: DataUnitId | null) =>
      createDataUnit({
        view: VIEW,
        controlHead: VIEW.state.head,
        actor: OWNER,
        dek: DEK0,
        sequences,
        previousUnitId,
        profile: TEXT,
        value,
      });
    const u1 = await make("one", null);
    const u2 = await make("two", u1.unitId);
    await sequences.reserveNext(VIEW.state.resourceId, OWNER.descriptor.principalId); // 3
    const u4 = await make("four", u2.unitId);
    expect(u4.seq).toBe(4n);
    await applier.receive(VIEW, u1.bytes);
    expect(await applier.receive(VIEW, u4.bytes)).toMatchObject({ kind: "held", reason: "GAP" });
    const second = await applier.receive(VIEW, u2.bytes);
    expect(second.kind === "applied" && second.released.map((r) => r.kind)).toEqual(["applied"]);
    expect(merged).toEqual(["one", "two", "four"]);
  });

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

  it("accepts a unit a loaded Snapshot covers without merging it, so the next unit links (§29, §26.2)", async () => {
    const merged: string[] = [];
    const storage = new InMemoryLfcpStorage();
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [textHandler(merged) as DataProfileHandler<unknown>],
    });
    const [, u2, u3, u4] = (await units("one", "two", "three", "four")) as {
      bytes: Uint8Array;
      unitId: DataUnitId;
    }[];
    // A Snapshot covered 1..2; 4 arrives first and is held, then 2 (covered), then 3.
    expect(await applier.receive(VIEW, (u4 as { bytes: Uint8Array }).bytes)).toMatchObject({
      kind: "held",
    });
    const covered = await applier.acceptCovered(VIEW, (u2 as { bytes: Uint8Array }).bytes);
    expect(covered).toMatchObject({ kind: "covered", released: [] });
    expect(await storage.dataUnits.get((u2 as { unitId: DataUnitId }).unitId)).toMatchObject({
      status: "merged",
      accepted: true,
      detail: "covered by a Snapshot",
    });
    const third = await applier.receive(VIEW, (u3 as { bytes: Uint8Array }).bytes);
    expect(third.kind === "applied" && third.released.map((r) => r.kind)).toEqual(["applied"]);
    expect(merged).toEqual(["three", "four"]); // "two" was never decrypted or merged
    expect(await applier.acceptCovered(VIEW, (u2 as { bytes: Uint8Array }).bytes)).toMatchObject({
      kind: "duplicate",
    });
  });
});

describe("DataUnitApplier.receiveBatch", () => {
  /** A text profile with applyBatch, counting its calls; "boom" is refused, "wait" buffered. */
  function batchHandler(log: { calls: number; merged: string[] }): DataProfileHandler<string> {
    return {
      ...textHandler(log.merged),
      applyBatch: (batch) => {
        log.calls += 1;
        const merged: DataUnitId[] = [];
        const pending: DataUnitId[] = [];
        const rejected: { unitId: DataUnitId; code: string; message: string }[] = [];
        for (const { unit, value } of batch) {
          if (value === "boom")
            rejected.push({ unitId: unit.unitId, code: "TEXT_REFUSED", message: "refused" });
          else if (value === "wait") pending.push(unit.unitId);
          else {
            log.merged.push(value);
            merged.push(unit.unitId);
          }
        }
        return { merged, pending, rejected, objects: ["o"], diagnostics: [] };
      },
    };
  }
  const applier = (handler: DataProfileHandler<string>) =>
    new DataUnitApplier({
      storage: new InMemoryLfcpStorage(),
      dek: () => DEK0,
      handlers: [handler],
    });

  it("checks every unit and hands the accepted ones to the profile in one call, in order", async () => {
    const log = { calls: 0, merged: [] as string[] };
    const a = applier(batchHandler(log));
    const u = await units("a", "b", "boom", "wait", "c");
    const outcomes = await a.receiveBatch(
      VIEW,
      u.map((x) => x.bytes),
    );
    expect(log.calls).toBe(1);
    expect(log.merged).toEqual(["a", "b", "c"]);
    expect(outcomes.map((o) => o.kind)).toEqual([
      "applied",
      "applied",
      "profile-rejected",
      "profile-pending",
      "applied",
    ]);
    // The batch's objects are reported once, on the last unit merged.
    expect(outcomes.map((o) => ("objects" in o ? o.objects : null))).toEqual([
      [],
      [],
      null,
      null,
      ["o"],
    ]);
    // Receiving them again: duplicates, nothing reaches the profile.
    const again = await a.receiveBatch(
      VIEW,
      u.map((x) => x.bytes),
    );
    expect(again.every((o) => o.kind === "duplicate")).toBe(true);
    expect(log.calls).toBe(1);
  });

  it("releases held units once, after the batch, on the unit they link to (§26.2)", async () => {
    const log = { calls: 0, merged: [] as string[] };
    const a = applier(batchHandler(log));
    const [u1, u2, u3] = (await units("a", "b", "c")).map((u) => u.bytes);
    if (u1 === undefined || u2 === undefined || u3 === undefined) throw new Error("units");
    expect((await a.receive(VIEW, u3)).kind).toBe("held");
    const outcomes = await a.receiveBatch(VIEW, [u1, u2]);
    expect(outcomes.map((o) => o.kind)).toEqual(["applied", "applied"]);
    const second = outcomes[1];
    const released = second !== undefined && "released" in second ? second.released : [];
    expect(released.map((o) => o.kind)).toEqual(["applied"]);
    expect(log.merged).toEqual(["a", "b", "c"]);
  });

  it("falls back to one unit at a time without applyBatch, or when it throws", async () => {
    const plain: string[] = [];
    const u = await units("a", "boom", "b");
    const outcomes = await applier(textHandler(plain)).receiveBatch(
      VIEW,
      u.map((x) => x.bytes),
    );
    expect(outcomes.map((o) => o.kind)).toEqual(["applied", "profile-rejected", "applied"]);
    expect(plain).toEqual(["a", "b"]);
    const throwing: string[] = [];
    const failing = applier({
      ...textHandler(throwing),
      applyBatch: () => {
        throw new Error("the profile failed as a whole");
      },
    });
    const isolated = await failing.receiveBatch(
      VIEW,
      u.map((x) => x.bytes),
    );
    expect(isolated.map((o) => o.kind)).toEqual(["applied", "profile-rejected", "applied"]);
    expect(throwing).toEqual(["a", "b"]);
  });
});
