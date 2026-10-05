import {
  actorSequence,
  controlRecordId,
  dataEpoch,
  dataUnitId,
  hash32,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  type ControlRecordRow,
  type DataUnitRow,
  dekSecretRef,
  InMemoryLfcpStorage,
  InMemorySecretStore,
  isSecretRef,
  type KeyPackageRow,
  principalKeySecretRef,
  type SnapshotRow,
  type StorageWrite,
  secretRef,
} from "../src/index.js";

// The storage contracts on the in-memory adapter (tests and development
// only). A durable adapter (LFCP-035) runs the same contracts.

const id = (b: number) => new Uint8Array(32).fill(b);
const R = resourceId(id(1));
const R2 = resourceId(id(2));
const ALICE = principalId(id(10));
const BOB = principalId(id(11));
const E0 = dataEpoch(0n);
const E1 = dataEpoch(1n);

const record = (n: number, prev: number | null): ControlRecordRow => ({
  recordId: controlRecordId(id(100 + n)),
  resourceId: R,
  controlSeq: BigInt(n),
  prevControlId: prev === null ? null : controlRecordId(id(100 + prev)),
  bytes: Uint8Array.of(0xd2, n, 1, 2, 3),
});

const unit = (n: number, seq: bigint, actor = ALICE, prev: number | null = null): DataUnitRow => ({
  unitId: dataUnitId(id(150 + n)),
  resourceId: R,
  dataEpoch: E0,
  actor,
  actorSeq: actorSequence(seq),
  prevDataUnitId: prev === null ? null : dataUnitId(id(150 + prev)),
  controlHead: controlRecordId(id(100)),
  bytes: Uint8Array.of(0xd2, 0x84, n, Number(seq)),
});

const keyPackage = (n: number, epoch = E0, recipient = BOB): KeyPackageRow => ({
  packageId: hash32(id(200 + n)),
  resourceId: R,
  dataEpoch: epoch,
  recipient,
  sender: ALICE,
  bytes: Uint8Array.of(0xd2, 0x25, n),
});

const ok = async (s: InMemoryLfcpStorage, writes: readonly StorageWrite[]) =>
  expect(await s.commit(writes)).toEqual({ ok: true });

describe("InMemoryLfcpStorage (tests and development only)", () => {
  it("1, 8. keeps Control Records' exact bytes and the head, set by compare-and-set", async () => {
    const s = new InMemoryLfcpStorage();
    const genesis = record(0, null);
    const grant = record(1, 0);
    await ok(s, [
      { op: "put-control-records", records: [grant, genesis] },
      {
        op: "set-control-head",
        resourceId: R,
        expected: null,
        head: { head: genesis.recordId, controlSeq: 0n },
      },
    ]);
    expect(await s.control.record(genesis.recordId)).toEqual(genesis);
    expect((await s.control.records(R)).map((r) => r.controlSeq)).toEqual([0n, 1n]);
    expect(await s.control.head(R)).toEqual({ head: genesis.recordId, controlSeq: 0n });
    // A stale expectation writes nothing at all, not even the records in the same batch.
    const stale = await s.commit([
      { op: "put-control-records", records: [record(2, 1)] },
      {
        op: "set-control-head",
        resourceId: R,
        expected: null,
        head: { head: grant.recordId, controlSeq: 1n },
      },
    ]);
    expect(stale).toEqual({
      ok: false,
      reason: "CONTROL_HEAD_MISMATCH",
      resourceId: R,
      current: genesis.recordId,
    });
    expect(await s.control.records(R)).toHaveLength(2);
    await ok(s, [
      {
        op: "set-control-head",
        resourceId: R,
        expected: genesis.recordId,
        head: { head: grant.recordId, controlSeq: 1n },
      },
    ]);
    expect((await s.control.head(R))?.controlSeq).toBe(1n);
    // Same ID, other bytes: refused, nothing written.
    await expect(
      s.commit([{ op: "put-control-records", records: [{ ...genesis, bytes: Uint8Array.of(9) }] }]),
    ).rejects.toMatchObject({ code: "INVALID_STRUCTURE" });
    expect(await s.control.record(genesis.recordId)).toEqual(genesis);
  });

  it("keeps a Control conflict and the epoch history with DEK references", async () => {
    const s = new InMemoryLfcpStorage();
    const heads = [controlRecordId(id(120)), controlRecordId(id(121))];
    await ok(s, [
      { op: "set-control-conflict", resourceId: R, conflict: { heads } },
      {
        op: "put-epoch",
        resourceId: R,
        epoch: {
          epoch: E1,
          dekCommitment: hash32(id(31)),
          openedBy: heads[0] as never,
          closedBy: null,
          dekRef: dekSecretRef(R, E1),
        },
      },
      {
        op: "put-epoch",
        resourceId: R,
        epoch: {
          epoch: E0,
          dekCommitment: hash32(id(30)),
          openedBy: controlRecordId(id(100)),
          closedBy: heads[0] as never,
          dekRef: null,
        },
      },
    ]);
    expect(await s.control.conflict(R)).toEqual({ heads });
    expect((await s.control.epochs(R)).map((e) => [e.epoch, e.dekRef])).toEqual([
      [0n, null],
      [1n, dekSecretRef(R, E1)],
    ]);
    await ok(s, [{ op: "set-control-conflict", resourceId: R, conflict: null }]);
    expect(await s.control.conflict(R)).toBeUndefined();
  });

  it("2, 3, 4. keeps Data Unit bytes, treats a repeat as a duplicate, and exposes an equivocating pair", async () => {
    const s = new InMemoryLfcpStorage();
    const a = unit(1, 1n);
    expect(await s.dataUnits.recordSeen(a)).toEqual({ unitIds: [a.unitId], firstSeen: true });
    expect(await s.dataUnits.recordSeen(a)).toEqual({ unitIds: [a.unitId], firstSeen: false });
    expect(await s.dataUnits.get(a.unitId)).toMatchObject({
      bytes: a.bytes,
      status: "seen",
      accepted: false,
    });
    const twin = unit(2, 1n);
    const seen = await s.dataUnits.recordSeen(twin);
    expect(seen.unitIds.map(toHex)).toEqual([a.unitId, twin.unitId].map(toHex));
    expect(await s.dataUnits.at(R, ALICE, actorSequence(1n))).toHaveLength(2);
    await expect(s.dataUnits.recordSeen({ ...a, bytes: Uint8Array.of(1) })).rejects.toMatchObject({
      code: "INVALID_STRUCTURE",
    });
  });

  it("marks, finds and un-accepts accepted units, and indexes them by status and range", async () => {
    const s = new InMemoryLfcpStorage();
    const [u1, u2, u3] = [unit(1, 1n), unit(2, 2n, ALICE, 1), unit(3, 3n, ALICE, 2)];
    await ok(s, [
      { op: "put-data-unit", unit: u1 as DataUnitRow, status: "merged", accepted: true },
      { op: "put-data-unit", unit: u2 as DataUnitRow, status: "merged", accepted: true },
      { op: "put-data-unit", unit: u3 as DataUnitRow, status: "held", detail: "GAP" },
    ]);
    expect(await s.dataUnits.acceptedAt(R, ALICE, actorSequence(2n))).toEqual(u2?.unitId);
    expect((await s.dataUnits.withStatus(R, "held")).map((u) => u.detail)).toEqual(["GAP"]);
    expect(
      (await s.dataUnits.range(R, ALICE, actorSequence(2n), actorSequence(3n))).map(
        (u) => u.actorSeq,
      ),
    ).toEqual([2n, 3n]);
    await ok(s, [
      { op: "set-accepted", unitId: (u2 as DataUnitRow).unitId, accepted: false },
      {
        op: "set-data-unit-status",
        unitId: (u2 as DataUnitRow).unitId,
        status: "quarantined",
        detail: "BEYOND_CUTOFF",
      },
    ]);
    expect(await s.dataUnits.acceptedAt(R, ALICE, actorSequence(2n))).toBeUndefined();
    expect(await s.dataUnits.get((u2 as DataUnitRow).unitId)).toMatchObject({
      status: "quarantined",
      accepted: false,
      bytes: u2?.bytes,
    });
    // A status write keeps the bytes; unknown units fail the whole batch.
    await expect(
      s.commit([
        { op: "set-data-unit-status", unitId: (u1 as DataUnitRow).unitId, status: "equivocation" },
        { op: "set-accepted", unitId: dataUnitId(id(99)), accepted: false },
      ]),
    ).rejects.toMatchObject({ code: "INVALID_STRUCTURE" });
    expect((await s.dataUnits.get((u1 as DataUnitRow).unitId))?.status).toBe("merged");
  });

  it("5. keeps several Key Packages for one (resource, epoch, recipient)", async () => {
    const s = new InMemoryLfcpStorage();
    await ok(
      s,
      [1, 2, 3].map((n) => ({ op: "put-key-package", row: keyPackage(n) }) as const),
    );
    await ok(s, [
      { op: "put-key-package", row: keyPackage(4, E1) },
      { op: "put-key-package", row: keyPackage(5, E0, ALICE) },
    ]);
    expect(await s.keyPackages.list(R, { epoch: E0, recipient: BOB })).toHaveLength(3);
    expect(await s.keyPackages.list(R, { epoch: E1 })).toEqual([keyPackage(4, E1)]);
    expect(await s.keyPackages.list(R2)).toEqual([]);
  });

  it("6. keeps Snapshot bytes and their selection metadata", async () => {
    const s = new InMemoryLfcpStorage();
    const snap: SnapshotRow = {
      snapshotId: hash32(id(210)),
      resourceId: R,
      dataEpoch: E1,
      publisher: ALICE,
      snapshotSeq: 3n,
      frontier: Uint8Array.of(0x81, 0x83),
      bytes: Uint8Array.of(0xd2, 0x29),
    };
    await ok(s, [{ op: "put-snapshot", row: snap }]);
    expect(await s.snapshots.get(snap.snapshotId)).toEqual(snap);
    expect(await s.snapshots.list(R, { epoch: E1 })).toEqual([snap]);
    expect(await s.snapshots.list(R, { epoch: E0 })).toEqual([]);
    expect(await s.snapshotSequences.reserveNext(R, E1, ALICE)).toBe(1n);
  });

  it("7. keeps routes, Resource metadata, outbound items and profile checkpoints", async () => {
    const s = new InMemoryLfcpStorage();
    const route = {
      routeVersion: 2n,
      endpoints: [{ url: "wss://a.example.test", priority: 0n }],
      coordinatorUrl: "wss://a.example.test",
      source: controlRecordId(id(103)),
    };
    const resource = {
      resourceId: R,
      dataProfile: "org.openlfcp.shared-objects.v1",
      localPrincipal: {
        principalId: ALICE,
        signingKeyRef: principalKeySecretRef(ALICE, "signing"),
        agreementKeyRef: principalKeySecretRef(ALICE, "agreement"),
      },
      labels: { name: "Project Alpha" },
    };
    const item = {
      itemId: hash32(id(160)),
      resourceId: R,
      kind: "data-unit" as const,
      bytes: Uint8Array.of(7),
      attempts: 0,
      lastAttempt: null,
    };
    const checkpoint = {
      resourceId: R,
      dataProfile: resource.dataProfile,
      state: Uint8Array.of(0x85, 0x6f),
      actorSeq: 4,
      units: [{ unitId: dataUnitId(id(151)), ref: "abc" }],
    };
    await ok(s, [
      { op: "put-route", resourceId: R, route },
      { op: "put-resource", row: resource },
      { op: "enqueue", item },
      { op: "enqueue", item: { ...item, itemId: hash32(id(161)) } },
      { op: "put-profile-checkpoint", checkpoint },
    ]);
    expect(await s.resources.route(R)).toEqual(route);
    expect(await s.resources.list()).toEqual([resource]);
    expect((await s.outbound.list(R)).map((o) => o.itemId)).toEqual([
      hash32(id(160)),
      hash32(id(161)),
    ]);
    await ok(s, [
      {
        op: "record-attempt",
        itemId: item.itemId,
        attempts: 1,
        lastAttempt: "2026-10-05T12:00:00Z",
      },
      { op: "dequeue", itemId: hash32(id(161)) },
    ]);
    expect(await s.outbound.list()).toEqual([
      { ...item, attempts: 1, lastAttempt: "2026-10-05T12:00:00Z" },
    ]);
    expect(await s.profileState.checkpoint(R)).toEqual(checkpoint);
  });

  it("10. reserves actor sequences through the atomic reservation contract", async () => {
    const s = new InMemoryLfcpStorage();
    const all = await Promise.all([1, 2, 3, 4].map(() => s.actorSequences.reserveNext(R, ALICE)));
    expect([...all].sort()).toEqual([1n, 2n, 3n, 4n]);
    expect(await s.actorSequences.reserveNext(R, BOB)).toBe(1n);
  });

  it("11. no caller buffer aliases a stored one, in or out", async () => {
    const s = new InMemoryLfcpStorage();
    const u = unit(1, 1n);
    const bytes = u.bytes;
    const unitIdBuf = u.unitId;
    await ok(s, [{ op: "put-data-unit", unit: u, status: "merged", accepted: true }]);
    bytes[0] = 0xff;
    const read = await s.dataUnits.get(dataUnitId(id(151)));
    expect(read?.bytes[0]).toBe(0xd2);
    (read?.bytes as Uint8Array)[0] = 0xee;
    unitIdBuf[0] = 0;
    expect((await s.dataUnits.get(dataUnitId(id(151))))?.bytes[0]).toBe(0xd2);
  });

  it("12. is deterministic: the same writes give the same reads", async () => {
    const run = async () => {
      const s = new InMemoryLfcpStorage();
      await s.commit([
        { op: "put-data-unit", unit: unit(3, 2n, BOB), status: "merged" },
        { op: "put-data-unit", unit: unit(1, 1n), status: "merged" },
        { op: "put-data-unit", unit: unit(2, 1n, BOB), status: "merged" },
        { op: "put-control-records", records: [record(1, 0), record(0, null)] },
      ]);
      return JSON.stringify(
        [await s.dataUnits.withStatus(R, "merged"), await s.control.records(R)],
        (_k, v: unknown) =>
          typeof v === "bigint" ? v.toString() : v instanceof Uint8Array ? toHex(v) : v,
      );
    };
    expect(await run()).toBe(await run());
  });
});

describe("secrets", () => {
  it("9. a reference names a secret without containing it, and the store cannot be enumerated or printed", async () => {
    const store = new InMemorySecretStore();
    const ref = dekSecretRef(R, E1);
    const dek = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
    expect(ref).toBe(`lfcp-secret:resource-dek:${toHex(R)}.1`);
    expect(isSecretRef(ref)).toBe(true);
    expect(ref).not.toContain(toHex(dek));
    await store.put(ref, dek);
    dek[0] = 0;
    expect((await store.get(ref))?.[0]).toBe(200);
    expect(JSON.stringify({ store })).toBe('{"store":"[InMemorySecretStore]"}');
    expect(String(store)).toBe("[InMemorySecretStore]");
    expect(Object.keys(store)).toEqual([]);
    expect("list" in store).toBe(false);
    await store.delete(ref);
    expect(await store.get(ref)).toBeUndefined();
    expect(() => secretRef("resource-dek", "has space")).toThrow();
    expect(isSecretRef("lfcp-secret:unknown:x")).toBe(false);
  });
});
