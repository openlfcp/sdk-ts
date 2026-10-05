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
  type DataProfileCodec,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  createDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
  EngineGuard,
  isEngineTrap,
  unitItem,
} from "../src/index.js";

// The crash-loop breaker (EngineGuard): a trap is injected through the
// profile handler (a WebAssembly.RuntimeError, as a trapped wasm engine
// throws), and a "restart" is a new applier on the same storage.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const OWNER: Signer = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};
const R = resourceId(bytes32(200));
const PROFILE = "org.example.text.v1";
const DEK0 = importResourceDEK(bytes32(90));
const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null as ControlRecordId | null },
  {
    type: "GENESIS",
    dataProfile: PROFILE,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  },
  OWNER,
);
const chain = validateControlChain([genesis.bytes]);
if (chain.kind !== "linear") throw new Error(chain.kind);
const VIEW: Extract<ChainResult, { kind: "linear" }> = chain;

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const text = (p: Uint8Array) => String.fromCharCode(...p);

/** The engine hook: values that trap, how often (Infinity: always). */
interface Engine {
  traps: Map<string, number>;
  /** A decode of these values traps too (always). */
  decodeTraps: Set<string>;
  merged: string[];
  calls: number;
}
const trap = () => new WebAssembly.RuntimeError("unreachable executed");

function engine(traps: Record<string, number> = {}, decodeTraps: string[] = []): Engine {
  return {
    traps: new Map(Object.entries(traps)),
    decodeTraps: new Set(decodeTraps),
    merged: [],
    calls: 0,
  };
}

/** A text profile with applyBatch and has(); a trap kills the batch, like a wasm trap. */
function handler(e: Engine): DataProfileHandler<string> {
  const ids = new Set<string>();
  const codec: DataProfileCodec<string> = {
    dataProfile: PROFILE,
    encode: ascii,
    decode: (p) => {
      if (e.decodeTraps.has(text(p))) throw trap();
      return text(p);
    },
  };
  const one = (unitId: DataUnitId, value: string) => {
    e.calls++;
    const left = e.traps.get(value) ?? 0;
    if (left > 0) {
      e.traps.set(value, left - 1);
      throw trap();
    }
    if (value === "refused") throw Object.assign(new Error("refused"), { code: "TEXT_REFUSED" });
    e.merged.push(value);
    ids.add(toHex(unitId));
  };
  return {
    dataProfile: PROFILE,
    codecFor: () => codec,
    has: (id) => ids.has(toHex(id)),
    apply: (unit, value) => {
      one(unit.unitId, value);
      return { merged: [unit.unitId], objects: [], diagnostics: [] };
    },
    applyBatch: (batch) => {
      for (const { unit, value } of batch) one(unit.unitId, value);
      return {
        merged: batch.map((b) => b.unit.unitId),
        pending: [],
        rejected: [],
        objects: [],
        diagnostics: [],
      };
    },
    exclude: () => ({ objects: [], pending: [] }),
  };
}

const applier = (storage: InMemoryLfcpStorage, e: Engine) =>
  new DataUnitApplier({
    storage,
    dek: () => DEK0,
    handlers: [handler(e) as DataProfileHandler<unknown>],
  });

type U = { bytes: Uint8Array; unitId: DataUnitId };

async function units(...values: string[]): Promise<U[]> {
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
        profile: { dataProfile: PROFILE, encode: ascii, decode: text },
        value,
      }),
    );
  return out;
}

const status = async (s: InMemoryLfcpStorage, id: DataUnitId) =>
  (await s.dataUnits.get(id))?.status;

describe("crash-loop breaker (EngineGuard)", () => {
  it("recognizes engine traps", () => {
    expect(isEngineTrap(trap())).toBe(true);
    expect(isEngineTrap(new Error("Automerge: the module was terminated"))).toBe(true);
    expect(isEngineTrap(new Error("refused"))).toBe(false);
    expect(isEngineTrap("unreachable")).toBe(false);
  });

  it("quarantines a poison unit after it crashed twice alone; its batch neighbours merge", async () => {
    const storage = new InMemoryLfcpStorage();
    const [a, poison, c] = (await units("a", "poison", "c")) as [U, U, U];
    const always = { poison: Number.POSITIVE_INFINITY };
    // Run 1: the batch traps; the process dies (the record stays).
    await expect(
      applier(storage, engine(always)).receiveBatch(
        VIEW,
        [a, poison, c].map((u) => u.bytes),
      ),
    ).rejects.toSatisfy(isEngineTrap);
    expect(await storage.localMarks.get(`applying:units:${toHex(R)}`)).toBeDefined();
    // Run 2 (restart): all three are suspects, replayed alone; "a" merges, the poison traps again.
    const e2 = engine(always);
    await expect(applier(storage, e2).replayStored(VIEW)).rejects.toSatisfy(isEngineTrap);
    expect(e2.merged).toEqual(["a"]);
    // Run 3: the poison crashed twice alone: quarantined, never given to the engine.
    const e3 = engine(always);
    const third = applier(storage, e3);
    const r = await third.replayStored(VIEW);
    expect(r.crashed.map(toHex)).toEqual([toHex(poison.unitId)]);
    expect([...e3.merged].sort()).toEqual(["a", "c"]); // a fresh profile state replays both good units
    expect(await status(storage, poison.unitId)).toBe("local-failure");
    expect((await storage.dataUnits.get(poison.unitId))?.detail).toMatch(
      /^INVALID_AUTOMERGE_BYTES/,
    );
    expect(await status(storage, c.unitId)).toBe("merged");
    // A re-delivered copy never reaches the engine either.
    const calls = e3.calls;
    expect(await third.receive(VIEW, poison.bytes)).toMatchObject({
      kind: "engine-crash",
      code: "INVALID_AUTOMERGE_BYTES",
    });
    expect(e3.calls).toBe(calls);
    // Reported once; the innocent units are no longer suspects.
    expect((await applier(storage, engine()).replayStored(VIEW)).crashed).toEqual([]);
    expect((await storage.localMarks.list(`suspect:${toHex(R)}:`)).map((m) => m.key)).toEqual([
      `suspect:${toHex(R)}:${unitItem(poison.unitId)}`,
    ]);
  });

  it("does not blame a unit for a single crash (the normal crash-restart path)", async () => {
    const storage = new InMemoryLfcpStorage();
    const [a, b] = (await units("a", "b")) as [U, U];
    // The process dies once inside the apply (here a trap; a kill looks the same).
    await expect(
      applier(storage, engine({ b: 1 })).receiveBatch(VIEW, [a.bytes, b.bytes]),
    ).rejects.toSatisfy(isEngineTrap);
    const e = engine();
    const r = await applier(storage, e).replayStored(VIEW);
    expect(r.crashed).toEqual([]);
    expect(e.merged).toEqual(["a", "b"]);
    expect(await status(storage, b.unitId)).toBe("merged");
    expect(await storage.localMarks.list("")).toEqual([]);
  });

  it("an ordinary profile refusal leaves no crash record", async () => {
    const storage = new InMemoryLfcpStorage();
    const [u] = (await units("refused")) as [U];
    const out = await applier(storage, engine()).receive(VIEW, u.bytes);
    expect(out.kind).toBe("profile-rejected");
    expect(await storage.localMarks.list("")).toEqual([]);
  });

  it("a trap in decode is rethrown, not recorded as the unit's local failure", async () => {
    const storage = new InMemoryLfcpStorage();
    const [u] = (await units("bad")) as [U];
    await expect(applier(storage, engine({}, ["bad"])).receive(VIEW, u.bytes)).rejects.toSatisfy(
      isEngineTrap,
    );
    expect(await storage.localMarks.get(`applying:units:${toHex(R)}`)).toBe(
      JSON.stringify([unitItem(u.unitId)]),
    );
  });

  it("keeps separate records per scope, and counts a crash once per restart", async () => {
    const storage = new InMemoryLfcpStorage();
    const units = new EngineGuard(storage, "units");
    const snapshots = new EngineGuard(storage, "snapshots");
    await units.recover(R);
    await snapshots.recover(R);
    const s = "snapshot:aa" as const;
    await expect(
      snapshots.run(R, [s], () => {
        throw trap();
      }),
    ).rejects.toSatisfy(isEngineTrap);
    await units.run(R, ["unit:bb"], () => undefined); // a unit apply meanwhile does not clear it
    const after = new EngineGuard(storage, "snapshots");
    expect(await after.recover(R)).toEqual([]);
    expect(after.suspicion(R, s)).toBe(1);
    expect(await after.recover(R)).toEqual([]); // once per guard: no double count
    expect(after.suspicion(R, s)).toBe(1);
  });
});
