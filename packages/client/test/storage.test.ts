import { type ControlRecordId, dataEpoch, hash32, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  InMemorySecretStore,
} from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  type DataProfileCodec,
  parseDataUnit,
  principalDescriptorFromKeys,
  receiveDataUnit,
  rotateEpoch,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  createQueuedDataUnit,
  dataUnitRow,
  dekResolver,
  latestAcceptedOwnUnit,
  loadControlChain,
  StoredSeenUnits,
  saveControlChain,
  saveControlConflict,
} from "../src/index.js";

// Client code over the storage interfaces (LFCP-034), on the in-memory
// adapter (tests and development only).

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const WRITER = signer(33);
const R = resourceId(bytes32(200));
const PROFILE = "org.example.text.v1";
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));

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
add({ type: "CAPABILITY_GRANT", subject: WRITER.descriptor, abilities: [1n, 2n], delegable: [] });

type Linear = Extract<ChainResult, { kind: "linear" }>;
const linear = (list: readonly Uint8Array[]): Linear => {
  const r = validateControlChain(list);
  if (r.kind !== "linear") throw new Error(r.kind);
  return r;
};
const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (p) => String.fromCharCode(...p),
};

describe("client over storage", () => {
  it("saves a validated chain atomically and loads it back from the exact bytes", async () => {
    const storage = new InMemoryLfcpStorage();
    const chain = linear(records);
    expect(await loadControlChain(storage, R)).toBeUndefined();
    expect(await saveControlChain(storage, chain, null)).toEqual({ ok: true });
    const loaded = await loadControlChain(storage, R);
    expect(loaded?.kind).toBe("linear");
    expect(loaded?.kind === "linear" && toHex(loaded.state.head)).toBe(toHex(chain.state.head));
    expect((await storage.control.records(R)).map((r) => toHex(r.bytes))).toEqual(
      records.map(toHex),
    );
    expect(await storage.resources.route(R)).toMatchObject({
      routeVersion: 0n,
      coordinatorUrl: "wss://a.example.test",
    });
    expect((await storage.control.epochs(R)).map((e) => e.epoch)).toEqual([0n]);
    // A writer that read an older head loses the compare-and-set and writes nothing.
    const rotation = rotateEpoch(chain.state, OWNER, { reason: 0n, finalFrontier: [], dek: DEK1 });
    const longer = linear([...records, rotation.bytes]);
    expect(await saveControlChain(storage, longer, null)).toMatchObject({
      ok: false,
      reason: "CONTROL_HEAD_MISMATCH",
    });
    expect(await storage.control.records(R)).toHaveLength(2);
    expect(await saveControlChain(storage, longer, chain.state.head)).toEqual({ ok: true });
    expect((await storage.control.epochs(R)).map((e) => [e.epoch, e.closedBy !== null])).toEqual([
      [0n, true],
      [1n, false],
    ]);
  });

  it("records a Control conflict", async () => {
    const storage = new InMemoryLfcpStorage();
    const other = signControlRecord(
      { resourceId: R, controlSeq: 1n, prevControlId: linear(records.slice(0, 1)).state.head },
      { type: "CAPABILITY_GRANT", subject: OWNER.descriptor, abilities: [1n], delegable: [] },
      OWNER,
    );
    const conflict = validateControlChain([...records, other.bytes]);
    if (conflict.kind !== "conflict") throw new Error(conflict.kind);
    expect(await saveControlConflict(storage, R, conflict)).toEqual({ ok: true });
    expect((await storage.control.conflict(R))?.heads.map(toHex)).toEqual(
      conflict.competing.map(toHex),
    );
  });

  it("resolves an epoch's DEK through its secret reference only", async () => {
    const storage = new InMemoryLfcpStorage();
    const secrets = new InMemorySecretStore();
    await saveControlChain(storage, linear(records), null);
    const dek = dekResolver(storage, secrets, R);
    expect(await dek(dataEpoch(0n))).toBeUndefined();
    const epoch0 = (await storage.control.epochs(R))[0] as EpochRow;
    await secrets.put(dekSecretRef(R, dataEpoch(0n)), bytes32(90));
    await storage.commit([
      {
        op: "put-epoch",
        resourceId: R,
        epoch: { ...epoch0, dekRef: dekSecretRef(R, dataEpoch(0n)) },
      },
    ]);
    expect(await dek(dataEpoch(0n))).toBeDefined();
    // Saving the chain again keeps the reference.
    await saveControlChain(storage, linear(records), linear(records).state.head);
    expect((await storage.control.epochs(R))[0]?.dekRef).toBe(dekSecretRef(R, dataEpoch(0n)));
  });

  it("keeps a DEK reference stored while a chain save is in flight (no lost update)", async () => {
    const storage = new InMemoryLfcpStorage();
    await saveControlChain(storage, linear(records), null);
    // A rotation arrives: the chain save reads the epoch rows, then commits.
    const rotation = rotateEpoch(linear(records).state, OWNER, {
      reason: 0n,
      finalFrontier: [],
      dek: DEK1,
    });
    const longer = linear([...records, rotation.bytes]);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const epochs = storage.control.epochs.bind(storage.control);
    storage.control.epochs = async (resource) => {
      const rows = await epochs(resource);
      await gate; // the save has read the rows and not yet committed
      return rows;
    };
    const saving = saveControlChain(storage, longer, linear(records).state.head);
    // Meanwhile a Key Package delivers epoch 0's DEK (as the sync client stores it).
    storage.control.epochs = epochs;
    const epoch0 = (await storage.control.epochs(R))[0] as EpochRow;
    await storage.commit([
      {
        op: "put-epoch",
        resourceId: R,
        epoch: { ...epoch0, dekRef: dekSecretRef(R, dataEpoch(0n)) },
      },
    ]);
    release();
    expect(await saving).toEqual({ ok: true });
    const after = await storage.control.epochs(R);
    expect(after.map((e) => [e.epoch, e.closedBy !== null, e.dekRef])).toEqual([
      [0n, true, dekSecretRef(R, dataEpoch(0n))],
      [1n, false, null],
    ]);
  });

  it("keeps an epoch closed when a DEK reference is stored from a row read before the close", async () => {
    const storage = new InMemoryLfcpStorage();
    await saveControlChain(storage, linear(records), null);
    // The sync client's Key Package path: read the epoch row, then (after
    // storing the secret) commit the row with its DEK reference.
    const read = (await storage.control.epochs(R))[0] as EpochRow;
    expect(read.closedBy).toBeNull();
    // Meanwhile the application saves a rotation that closes epoch 0.
    const rotation = rotateEpoch(linear(records).state, OWNER, {
      reason: 0n,
      finalFrontier: [],
      dek: DEK1,
    });
    const longer = linear([...records, rotation.bytes]);
    expect(await saveControlChain(storage, longer, linear(records).state.head)).toEqual({
      ok: true,
    });
    await storage.commit([
      {
        op: "put-epoch",
        resourceId: R,
        epoch: { ...read, dekRef: dekSecretRef(R, dataEpoch(0n)) },
      },
    ]);
    const after = await storage.control.epochs(R);
    expect(after.map((e) => [e.epoch, e.closedBy !== null, e.dekRef])).toEqual([
      [0n, true, dekSecretRef(R, dataEpoch(0n))],
      [1n, false, null],
    ]);
    // The reloaded chain and the stored epochs agree: epoch 0 is closed.
    const loaded = await loadControlChain(storage, R);
    expect(loaded?.kind === "linear" && loaded.state.epoch.epoch).toBe(1n);
  });

  it("creates a local unit with a stored sequence and commits it with its outbound entry", async () => {
    const storage = new InMemoryLfcpStorage();
    const view = linear(records);
    const base = { view, controlHead: view.state.head, actor: WRITER, dek: DEK0, profile: TEXT };
    const u1 = await createQueuedDataUnit(storage, { ...base, previousUnitId: null, value: "one" });
    const u2 = await createQueuedDataUnit(storage, {
      ...base,
      previousUnitId: u1.unitId,
      value: "two",
    });
    expect([u1.seq, u2.seq]).toEqual([1n, 2n]);
    expect(await storage.dataUnits.get(u1.unitId)).toMatchObject({
      status: "merged",
      accepted: true,
      bytes: u1.bytes,
    });
    expect((await storage.outbound.list(R)).map((o) => [o.kind, toHex(o.bytes)])).toEqual([
      ["data-unit", toHex(u1.bytes)],
      ["data-unit", toHex(u2.bytes)],
    ]);
    expect((await storage.outbound.get(hash32(u2.unitId)))?.attempts).toBe(0);
  });

  it("links each new unit to the latest own unit still accepted by default (§26.2, G-DP1-GAP)", async () => {
    const storage = new InMemoryLfcpStorage();
    const view = linear(records);
    const base = { view, controlHead: view.state.head, actor: WRITER, dek: DEK0, profile: TEXT };
    const prevOf = (bytes: Uint8Array) => parseDataUnit(bytes).payload.prevDataUnitId;
    const u1 = await createQueuedDataUnit(storage, { ...base, value: "one" });
    const u2 = await createQueuedDataUnit(storage, { ...base, value: "two" });
    expect(prevOf(u1.bytes)).toBeNull();
    expect(toHex(prevOf(u2.bytes) as Uint8Array)).toBe(toHex(u1.unitId));
    // A crash abandons a reserved sequence (3): the next unit is 4 and names 2.
    await storage.actorSequences.reserveNext(R, WRITER.descriptor.principalId);
    const u4 = await createQueuedDataUnit(storage, { ...base, value: "four" });
    expect([u4.seq, toHex(prevOf(u4.bytes) as Uint8Array)]).toEqual([4n, toHex(u2.unitId)]);
    // 4 goes stale (a cutoff excluded it, G-EP7): the re-applied work (G-EP5) names 2.
    await storage.commit([
      { op: "set-data-unit-status", unitId: u4.unitId, status: "quarantined", detail: "STALE" },
      { op: "set-accepted", unitId: u4.unitId, accepted: false },
    ]);
    const u5 = await createQueuedDataUnit(storage, { ...base, value: "five" });
    expect([u5.seq, toHex(prevOf(u5.bytes) as Uint8Array)]).toEqual([5n, toHex(u2.unitId)]);
    // 5 turns out to equivocate (G-DP5): the next unit names 2 again.
    await storage.commit([
      { op: "set-data-unit-status", unitId: u5.unitId, status: "equivocation" },
      { op: "set-accepted", unitId: u5.unitId, accepted: false },
    ]);
    const u6 = await createQueuedDataUnit(storage, { ...base, value: "six" });
    expect(toHex(prevOf(u6.bytes) as Uint8Array)).toBe(toHex(u2.unitId));
    expect(
      toHex((await latestAcceptedOwnUnit(storage, R, WRITER.descriptor.principalId)) as Uint8Array),
    ).toBe(toHex(u6.unitId));
  });

  it("runs the wire receive pipeline on durable SeenUnits with un-accept", async () => {
    const storage = new InMemoryLfcpStorage();
    const view = linear(records);
    const writer = new InMemoryLfcpStorage();
    const u = await createQueuedDataUnit(writer, {
      view,
      controlHead: view.state.head,
      actor: WRITER,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: null,
      value: "hello",
    });
    const seen = new StoredSeenUnits(storage);
    const receive = () => {
      seen.expect(dataUnitRow(u.bytes));
      return receiveDataUnit(view, u.bytes, { seen, dek: () => DEK0, profile: TEXT });
    };
    expect(await receive()).toMatchObject({ kind: "accepted", value: "hello" });
    expect(await receive()).toMatchObject({ kind: "duplicate" });
    expect(await storage.dataUnits.get(u.unitId)).toMatchObject({ accepted: true, bytes: u.bytes });
    await storage.commit([{ op: "set-accepted", unitId: u.unitId, accepted: false }]);
    expect(await receive()).toMatchObject({ kind: "accepted" });
  });
});
