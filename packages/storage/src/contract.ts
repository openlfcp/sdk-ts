import {
  actorSequence,
  bytesEqual,
  controlRecordId,
  dataEpoch,
  dataUnitId,
  hash32,
  LfcpError,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { dekSecretRef, isSecretRef, principalKeySecretRef, type SecretStore } from "./secrets.js";
import type {
  ControlRecordRow,
  DataUnitRow,
  KeyPackageRow,
  LfcpStorage,
  SnapshotRow,
  StorageWrite,
} from "./store.js";

/**
 * The LfcpStorage and SecretStore contracts as a reusable test suite
 * (LFCP-034, LFCP-035): every adapter (in-memory, Node, Obsidian) runs the
 * same checks. It takes the test runner's describe/it and uses its own
 * assertions, so this package does not depend on a test framework.
 *
 *   runStorageContract({ describe, it }, "InMemoryLfcpStorage", open)
 *
 * `open` gives a fresh, isolated store per test. A durable adapter also
 * implements reopen(), and the suite then checks that state survives.
 */

/** The parts of a test runner the suite needs (vitest, node:test, mocha, …). */
export interface ContractTestApi {
  describe(name: string, fn: () => void): void;
  it(name: string, fn: () => Promise<void>): void;
}

export interface StorageContractStore {
  readonly storage: LfcpStorage;
  readonly secrets: SecretStore;
}

export interface StorageContractHarness extends StorageContractStore {
  /** Durable adapters only: closes the store and opens it again on the same location. */
  reopen?(): Promise<StorageContractStore>;
  /** Releases the store and deletes its location. */
  close(): Promise<void>;
}

// ---------------------------------------------------------------------------
// assertions (no test framework)

/** A canonical rendering: bigints and bytes spelled out, object keys sorted (rows from any adapter compare equal). */
const show = (v: unknown): string =>
  JSON.stringify(v, (_k, x: unknown) => {
    if (typeof x === "bigint") return `${x}n`;
    if (x instanceof Uint8Array) return `0x${toHex(x)}`;
    if (x !== null && typeof x === "object" && !Array.isArray(x))
      return Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1)));
    return x;
  });

function eq(actual: unknown, expected: unknown, what: string): void {
  const [a, e] = [show(actual), show(expected)];
  if (a !== e) throw new Error(`${what}: expected ${e}, got ${a}`);
}

async function rejectsWith(p: Promise<unknown>, code: string, what: string): Promise<void> {
  try {
    await p;
  } catch (e) {
    if (e instanceof LfcpError && e.code === code) return;
    throw new Error(`${what}: expected ${code}, got ${String(e)}`);
  }
  throw new Error(`${what}: expected ${code}, but it resolved`);
}

// ---------------------------------------------------------------------------
// fixtures

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
  bytes: Uint8Array.of(0xd2, n, 0, 0xff, 0x80, 1, 2, 3),
});

const unit = (n: number, seq: bigint, actor = ALICE, prev: number | null = null): DataUnitRow => ({
  unitId: dataUnitId(id(150 + n)),
  resourceId: R,
  dataEpoch: E0,
  actor,
  actorSeq: actorSequence(seq),
  prevDataUnitId: prev === null ? null : dataUnitId(id(150 + prev)),
  controlHead: controlRecordId(id(100)),
  bytes: Uint8Array.of(0xd2, 0x84, n, Number(seq), 0, 0xff),
});

const keyPackage = (n: number, epoch = E0, recipient = BOB): KeyPackageRow => ({
  packageId: hash32(id(200 + n)),
  resourceId: R,
  dataEpoch: epoch,
  recipient,
  sender: ALICE,
  bytes: Uint8Array.of(0xd2, 0x25, n, 0),
});

const snapshot: SnapshotRow = {
  snapshotId: hash32(id(210)),
  resourceId: R,
  dataEpoch: E1,
  publisher: ALICE,
  snapshotSeq: 3n,
  frontier: Uint8Array.of(0x81, 0x83),
  bytes: Uint8Array.of(0xd2, 0x29, 0),
};

const route = {
  routeVersion: 2n,
  endpoints: [
    { url: "wss://a.example.test", priority: 0n },
    { url: "wss://b.example.test", priority: 1n, flags: 0n },
  ],
  coordinatorUrl: "wss://a.example.test",
  source: controlRecordId(id(103)),
};

const resourceRow = {
  resourceId: R,
  dataProfile: "org.openlfcp.shared-objects.v1",
  localPrincipal: {
    principalId: ALICE,
    signingKeyRef: principalKeySecretRef(ALICE, "signing"),
    agreementKeyRef: principalKeySecretRef(ALICE, "agreement"),
  },
  labels: { name: "Project Alpha" },
};

const checkpoint = {
  resourceId: R,
  dataProfile: resourceRow.dataProfile,
  state: Uint8Array.of(0x85, 0x6f, 0x4a, 0x83, 0),
  actorSeq: 4,
  units: [{ unitId: dataUnitId(id(151)), ref: "abc" }],
};

const epochRows = [
  {
    epoch: E0,
    dekCommitment: hash32(id(30)),
    openedBy: controlRecordId(id(100)),
    closedBy: controlRecordId(id(103)),
    dekRef: null,
  },
  {
    epoch: E1,
    dekCommitment: hash32(id(31)),
    openedBy: controlRecordId(id(103)),
    closedBy: null,
    dekRef: dekSecretRef(R, E1),
  },
];

async function ok(s: LfcpStorage, writes: readonly StorageWrite[], what: string): Promise<void> {
  eq(await s.commit(writes), { ok: true }, what);
}

// ---------------------------------------------------------------------------

export function runStorageContract(
  t: ContractTestApi,
  name: string,
  open: () => Promise<StorageContractHarness>,
): void {
  const test = (title: string, fn: (h: StorageContractHarness) => Promise<void>) =>
    t.it(title, async () => {
      const h = await open();
      try {
        await fn(h);
      } finally {
        await h.close();
      }
    });

  t.describe(`LfcpStorage contract: ${name}`, () => {
    test("keeps Control Records' exact bytes and sets the head by compare-and-set", async ({
      storage: s,
    }) => {
      const genesis = record(0, null);
      const grant = record(1, 0);
      await ok(
        s,
        [
          { op: "put-control-records", records: [grant, genesis] },
          {
            op: "set-control-head",
            resourceId: R,
            expected: null,
            head: { head: genesis.recordId, controlSeq: 0n },
          },
        ],
        "first batch",
      );
      eq(await s.control.record(genesis.recordId), genesis, "record");
      eq(
        (await s.control.records(R)).map((r) => r.controlSeq),
        [0n, 1n],
        "records in order",
      );
      eq(await s.control.head(R), { head: genesis.recordId, controlSeq: 0n }, "head");
      const stale = await s.commit([
        { op: "put-control-records", records: [record(2, 1)] },
        {
          op: "set-control-head",
          resourceId: R,
          expected: null,
          head: { head: grant.recordId, controlSeq: 1n },
        },
      ]);
      eq(
        stale,
        { ok: false, reason: "CONTROL_HEAD_MISMATCH", resourceId: R, current: genesis.recordId },
        "stale head",
      );
      eq((await s.control.records(R)).length, 2, "nothing of the failed batch written");
      await ok(
        s,
        [
          {
            op: "set-control-head",
            resourceId: R,
            expected: genesis.recordId,
            head: { head: grant.recordId, controlSeq: 1n },
          },
        ],
        "advance",
      );
      eq((await s.control.head(R))?.controlSeq, 1n, "advanced");
      await rejectsWith(
        s.commit([
          { op: "put-control-records", records: [record(5, 4)] },
          { op: "put-control-records", records: [{ ...genesis, bytes: Uint8Array.of(9) }] },
        ]),
        "INVALID_STRUCTURE",
        "same ID, other bytes",
      );
      eq(await s.control.record(genesis.recordId), genesis, "unchanged");
      eq(
        await s.control.record(record(5, 4).recordId),
        undefined,
        "nothing of the refused batch written",
      );
      eq(await s.control.records(R2), [], "other Resource");
    });

    test("keeps a Control conflict and the epoch history with DEK references", async ({
      storage: s,
    }) => {
      const heads = [controlRecordId(id(120)), controlRecordId(id(121))];
      await ok(
        s,
        [
          { op: "set-control-conflict", resourceId: R, conflict: { heads } },
          { op: "put-epoch", resourceId: R, epoch: epochRows[1] as never },
          { op: "put-epoch", resourceId: R, epoch: epochRows[0] as never },
        ],
        "conflict and epochs",
      );
      eq(await s.control.conflict(R), { heads }, "conflict");
      eq(await s.control.epochs(R), epochRows, "epochs ascending");
      await ok(s, [{ op: "set-control-conflict", resourceId: R, conflict: null }], "clear");
      eq(await s.control.conflict(R), undefined, "cleared");
    });

    test("keeps Data Unit bytes, treats a repeat as a duplicate and exposes an equivocating pair", async ({
      storage: s,
    }) => {
      const a = unit(1, 1n);
      eq(await s.dataUnits.recordSeen(a), { unitIds: [a.unitId], firstSeen: true }, "first");
      eq(await s.dataUnits.recordSeen(a), { unitIds: [a.unitId], firstSeen: false }, "repeat");
      const stored = await s.dataUnits.get(a.unitId);
      eq(
        [stored?.bytes, stored?.status, stored?.accepted, stored?.detail],
        [a.bytes, "seen", false, null],
        "stored",
      );
      eq(stored?.actorSeq, 1n, "header index");
      const twin = unit(2, 1n);
      eq(
        (await s.dataUnits.recordSeen(twin)).unitIds.map(toHex),
        [a.unitId, twin.unitId].map(toHex),
        "both IDs at the tuple",
      );
      eq((await s.dataUnits.at(R, ALICE, actorSequence(1n))).length, 2, "at");
      await rejectsWith(
        s.dataUnits.recordSeen({ ...a, bytes: Uint8Array.of(1) }),
        "INVALID_STRUCTURE",
        "other bytes",
      );
    });

    test("marks, finds and un-accepts accepted units, and indexes them by status and range", async ({
      storage: s,
    }) => {
      const [u1, u2, u3] = [unit(1, 1n), unit(2, 2n, ALICE, 1), unit(3, 3n, ALICE, 2)];
      await ok(
        s,
        [
          { op: "put-data-unit", unit: u1, status: "merged", accepted: true },
          { op: "put-data-unit", unit: u2, status: "merged", accepted: true },
          { op: "put-data-unit", unit: u3, status: "held", detail: "GAP" },
          { op: "put-data-unit", unit: unit(4, 1n, BOB), status: "merged" },
        ],
        "units",
      );
      eq(await s.dataUnits.acceptedAt(R, ALICE, actorSequence(2n)), u2.unitId, "acceptedAt");
      eq(
        (await s.dataUnits.withStatus(R, "held")).map((u) => u.detail),
        ["GAP"],
        "withStatus",
      );
      eq(
        (await s.dataUnits.range(R, ALICE, actorSequence(2n), actorSequence(3n))).map(
          (u) => u.actorSeq,
        ),
        [2n, 3n],
        "range",
      );
      eq((await s.dataUnits.withStatus(R, "merged")).length, 3, "merged");
      await ok(
        s,
        [
          { op: "set-accepted", unitId: u2.unitId, accepted: false },
          {
            op: "set-data-unit-status",
            unitId: u2.unitId,
            status: "quarantined",
            detail: "BEYOND_CUTOFF",
          },
        ],
        "un-accept",
      );
      eq(await s.dataUnits.acceptedAt(R, ALICE, actorSequence(2n)), undefined, "un-accepted");
      const u2s = await s.dataUnits.get(u2.unitId);
      eq(
        [u2s?.status, u2s?.accepted, u2s?.detail, u2s?.bytes],
        ["quarantined", false, "BEYOND_CUTOFF", u2.bytes],
        "status kept bytes",
      );
      // put-data-unit of a stored unit keeps its accepted mark unless given.
      await ok(s, [{ op: "put-data-unit", unit: u1, status: "profile-pending" }], "status only");
      eq((await s.dataUnits.get(u1.unitId))?.accepted, true, "accepted kept");
      await rejectsWith(
        s.commit([
          { op: "set-data-unit-status", unitId: u1.unitId, status: "equivocation" },
          { op: "set-accepted", unitId: dataUnitId(id(99)), accepted: false },
        ]),
        "INVALID_STRUCTURE",
        "unknown unit",
      );
      eq(
        (await s.dataUnits.get(u1.unitId))?.status,
        "profile-pending",
        "nothing of the refused batch written",
      );
    });

    test("keeps several Key Packages for one (resource, epoch, recipient)", async ({
      storage: s,
    }) => {
      await ok(
        s,
        [1, 2, 3].map((n) => ({ op: "put-key-package", row: keyPackage(n) }) as const),
        "three",
      );
      await ok(
        s,
        [
          { op: "put-key-package", row: keyPackage(4, E1) },
          { op: "put-key-package", row: keyPackage(5, E0, ALICE) },
          { op: "put-key-package", row: keyPackage(1) },
        ],
        "more, one repeated",
      );
      eq((await s.keyPackages.list(R, { epoch: E0, recipient: BOB })).length, 3, "per recipient");
      eq(await s.keyPackages.list(R, { epoch: E1 }), [keyPackage(4, E1)], "per epoch");
      eq((await s.keyPackages.list(R)).length, 5, "all");
      eq(await s.keyPackages.get(keyPackage(2).packageId), keyPackage(2), "get");
      eq(await s.keyPackages.list(R2), [], "other Resource");
    });

    test("keeps Snapshot bytes and their selection metadata", async ({ storage: s }) => {
      await ok(s, [{ op: "put-snapshot", row: snapshot }], "snapshot");
      eq(await s.snapshots.get(snapshot.snapshotId), snapshot, "get");
      eq(await s.snapshots.list(R, { epoch: E1 }), [snapshot], "list");
      eq(await s.snapshots.list(R, { epoch: E0 }), [], "other epoch");
    });

    test("keeps routes, Resource metadata, outbound items and profile checkpoints", async ({
      storage: s,
    }) => {
      const item = {
        itemId: hash32(id(160)),
        resourceId: R,
        kind: "data-unit" as const,
        bytes: Uint8Array.of(7, 0),
        attempts: 0,
        lastAttempt: null,
        nextAttempt: null,
        blocked: null,
      };
      const second = { ...item, itemId: hash32(id(161)), kind: "key-package" as const };
      const third = { ...item, itemId: hash32(id(159)), resourceId: R2 };
      await ok(
        s,
        [
          { op: "put-route", resourceId: R, route },
          { op: "put-resource", row: resourceRow },
          { op: "enqueue", item },
          { op: "enqueue", item: second },
          { op: "enqueue", item: third },
          { op: "put-profile-checkpoint", checkpoint },
        ],
        "batch",
      );
      eq(await s.resources.route(R), route, "route");
      eq(await s.resources.get(R), resourceRow, "resource");
      eq(await s.resources.list(), [resourceRow], "resources");
      eq(
        (await s.outbound.list(R)).map((o) => o.itemId),
        [item.itemId, second.itemId],
        "enqueue order",
      );
      eq((await s.outbound.list()).length, 3, "all outbound");
      await ok(
        s,
        [
          {
            op: "update-outbound",
            itemId: item.itemId,
            attempts: 1,
            lastAttempt: "2026-10-05T12:00:00Z",
            nextAttempt: "2026-10-05T12:00:30Z",
          },
          { op: "dequeue", itemId: second.itemId },
          {
            op: "update-outbound",
            itemId: third.itemId,
            blocked: { reason: "stale-epoch", detail: "BEYOND_CUTOFF" },
          },
        ],
        "attempt, block and dequeue",
      );
      eq(
        await s.outbound.list(R),
        [
          {
            ...item,
            attempts: 1,
            lastAttempt: "2026-10-05T12:00:00Z",
            nextAttempt: "2026-10-05T12:00:30Z",
          },
        ],
        "after",
      );
      eq(
        await s.outbound.get(third.itemId),
        { ...third, blocked: { reason: "stale-epoch", detail: "BEYOND_CUTOFF" } },
        "blocked, other fields kept",
      );
      await ok(
        s,
        [{ op: "update-outbound", itemId: third.itemId, blocked: null, nextAttempt: null }],
        "unblock",
      );
      eq((await s.outbound.get(third.itemId))?.blocked, null, "unblocked");
      await rejectsWith(
        s.commit([{ op: "update-outbound", itemId: hash32(id(170)), attempts: 1 }]),
        "INVALID_STRUCTURE",
        "unknown item",
      );
      const sync = {
        resourceId: R,
        recentlyAcked: [hash32(id(161)), hash32(id(160))],
        ackedDurability: 2n,
      };
      eq(await s.syncState.get(R), undefined, "no sync state yet");
      await ok(s, [{ op: "put-sync-state", row: sync }], "sync state");
      eq(await s.syncState.get(R), sync, "sync state");
      await ok(
        s,
        [{ op: "put-sync-state", row: { ...sync, recentlyAcked: [], ackedDurability: null } }],
        "replace",
      );
      eq(
        await s.syncState.get(R),
        { ...sync, recentlyAcked: [], ackedDurability: null },
        "replaced",
      );
      eq(await s.profileState.checkpoint(R), checkpoint, "checkpoint");
      await ok(
        s,
        [{ op: "put-profile-checkpoint", checkpoint: { ...checkpoint, actorSeq: 5 } }],
        "replace",
      );
      eq((await s.profileState.checkpoint(R))?.actorSeq, 5, "replaced");
    });

    test("reserves actor and Snapshot sequences without ever repeating one", async ({
      storage: s,
    }) => {
      const all = await Promise.all([1, 2, 3, 4].map(() => s.actorSequences.reserveNext(R, ALICE)));
      eq([...all].sort(), [1n, 2n, 3n, 4n], "concurrent reservations");
      eq(await s.actorSequences.reserveNext(R, BOB), 1n, "per principal");
      eq(await s.actorSequences.reserveNext(R2, ALICE), 1n, "per resource");
      eq(await s.snapshotSequences.reserveNext(R, E1, ALICE), 1n, "snapshot");
      eq(await s.snapshotSequences.reserveNext(R, E1, ALICE), 2n, "snapshot next");
      eq(await s.snapshotSequences.reserveNext(R, E0, ALICE), 1n, "per epoch");
    });

    test("fails closed when a reservation counter is behind the Principal's own stored objects", async ({
      storage: s,
    }) => {
      // Units of ALICE up to sequence 3 exist, but no reservation was recorded:
      // lost or damaged sequence state. Reserving must refuse, not hand out 1.
      await ok(
        s,
        [{ op: "put-data-unit", unit: unit(3, 3n), status: "merged", accepted: true }],
        "unit at 3",
      );
      await rejectsWith(
        s.actorSequences.reserveNext(R, ALICE),
        "SEQUENCE_REUSE",
        "actor sequence behind",
      );
      eq(await s.actorSequences.reserveNext(R, BOB), 1n, "another Principal is unaffected");
      await ok(s, [{ op: "put-snapshot", row: snapshot }], "Snapshot at sequence 3");
      await rejectsWith(
        s.snapshotSequences.reserveNext(R, E1, ALICE),
        "SEQUENCE_REUSE",
        "Snapshot sequence behind",
      );
      eq(await s.snapshotSequences.reserveNext(R, E0, ALICE), 1n, "another epoch is unaffected");
    });

    test("no caller buffer aliases a stored one, in or out", async ({ storage: s }) => {
      const u = unit(1, 1n);
      const bytes = u.bytes;
      await ok(s, [{ op: "put-data-unit", unit: u, status: "merged", accepted: true }], "unit");
      bytes[0] = 0xff;
      (u.unitId as Uint8Array)[0] = 0;
      const read = await s.dataUnits.get(dataUnitId(id(151)));
      eq(read?.bytes[0], 0xd2, "write side");
      (read?.bytes as Uint8Array)[0] = 0xee;
      eq((await s.dataUnits.get(dataUnitId(id(151))))?.bytes[0], 0xd2, "read side");
    });

    test("gives the same reads for the same writes", async ({ storage: s }) => {
      await ok(
        s,
        [
          { op: "put-data-unit", unit: unit(3, 2n, BOB), status: "merged" },
          { op: "put-data-unit", unit: unit(1, 1n), status: "merged" },
          { op: "put-data-unit", unit: unit(2, 1n, BOB), status: "merged" },
          { op: "put-control-records", records: [record(1, 0), record(0, null)] },
        ],
        "writes",
      );
      eq(
        (await s.dataUnits.withStatus(R, "merged")).map(
          (u) => `${toHex(u.actor).slice(0, 2)}:${u.actorSeq}`,
        ),
        ["0a:1", "0b:1", "0b:2"],
        "by (actor, seq)",
      );
      eq(
        (await s.control.records(R)).map((r) => r.controlSeq),
        [0n, 1n],
        "records by seq",
      );
    });

    test("SecretStore: a reference names a secret without containing it; values are copied", async ({
      secrets,
    }) => {
      const ref = dekSecretRef(R, E1);
      const dek = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
      eq(isSecretRef(ref), true, "ref");
      eq(ref.includes(toHex(dek)), false, "no value in the ref");
      eq(await secrets.get(ref), undefined, "absent");
      await secrets.put(ref, dek);
      dek[0] = 0;
      const got = await secrets.get(ref);
      eq(got?.[0], 200, "copied in");
      (got as Uint8Array)[1] = 0;
      eq((await secrets.get(ref))?.[1], 199, "copied out");
      await secrets.put(ref, Uint8Array.of(1));
      eq(await secrets.get(ref), Uint8Array.of(1), "replaced");
      await secrets.delete(ref);
      eq(await secrets.get(ref), undefined, "deleted");
      await secrets.delete(ref);
      eq("list" in secrets, false, "no enumeration");
      eq(String(secrets).includes("200"), false, "no value in String()");
    });

    test("durable adapters: everything committed survives a reopen", async (h) => {
      if (h.reopen === undefined) return; // the in-memory adapter forgets by design
      const s = h.storage;
      const u = unit(1, 1n);
      // Reserve first, as writers do (a stored unit ahead of its reservation fails closed).
      const seqs = [
        await s.actorSequences.reserveNext(R, ALICE),
        await s.actorSequences.reserveNext(R, ALICE),
      ];
      eq(seqs, [1n, 2n], "reserved");
      eq(await s.snapshotSequences.reserveNext(R, E1, BOB), 1n, "snapshot reserved");
      await ok(
        s,
        [
          { op: "put-control-records", records: [record(0, null), record(1, 0)] },
          {
            op: "set-control-head",
            resourceId: R,
            expected: null,
            head: { head: record(1, 0).recordId, controlSeq: 1n },
          },
          ...epochRows.map((epoch) => ({ op: "put-epoch", resourceId: R, epoch }) as const),
          { op: "put-route", resourceId: R, route },
          { op: "put-resource", row: resourceRow },
          { op: "put-data-unit", unit: u, status: "merged", accepted: true },
          { op: "put-key-package", row: keyPackage(1) },
          { op: "put-snapshot", row: snapshot },
          {
            op: "enqueue",
            item: {
              itemId: hash32(id(160)),
              resourceId: R,
              kind: "data-unit",
              bytes: Uint8Array.of(7),
              attempts: 0,
              lastAttempt: null,
              nextAttempt: "2026-10-05T12:01:00Z",
              blocked: { reason: "repropose", detail: null },
            },
          },
          {
            op: "put-sync-state",
            row: { resourceId: R, recentlyAcked: [hash32(id(160))], ackedDurability: 3n },
          },
          { op: "put-profile-checkpoint", checkpoint },
        ],
        "everything",
      );
      await h.secrets.put(dekSecretRef(R, E1), Uint8Array.of(42));

      const again = await h.reopen();
      const r = again.storage;
      eq(await r.control.head(R), { head: record(1, 0).recordId, controlSeq: 1n }, "head");
      eq(
        (await r.control.records(R)).map((x) => x.bytes),
        [record(0, null).bytes, record(1, 0).bytes],
        "records",
      );
      eq(await r.control.epochs(R), epochRows, "epochs");
      eq(await r.resources.route(R), route, "route");
      eq(await r.resources.get(R), resourceRow, "resource");
      eq(
        await r.dataUnits.get(u.unitId),
        { ...u, status: "merged", detail: null, accepted: true },
        "unit",
      );
      eq(await r.keyPackages.get(keyPackage(1).packageId), keyPackage(1), "key package");
      eq(await r.snapshots.get(snapshot.snapshotId), snapshot, "snapshot");
      eq((await r.outbound.list()).length, 1, "outbound");
      eq(await r.profileState.checkpoint(R), checkpoint, "checkpoint");
      eq(
        (await r.outbound.list()).map((o) => [o.nextAttempt, o.blocked]),
        [["2026-10-05T12:01:00Z", { reason: "repropose", detail: null }]],
        "outbound retry state",
      );
      eq(
        await r.syncState.get(R),
        { resourceId: R, recentlyAcked: [hash32(id(160))], ackedDurability: 3n },
        "sync state",
      );
      eq(await r.actorSequences.reserveNext(R, ALICE), 3n, "no sequence reuse after reopen");
      eq(
        await r.snapshotSequences.reserveNext(R, E1, BOB),
        2n,
        "no snapshot sequence reuse after reopen",
      );
      eq(await again.secrets.get(dekSecretRef(R, E1)), Uint8Array.of(42), "secret");
      if (
        !bytesEqual(
          record(0, null).bytes,
          (await r.control.records(R))[0]?.bytes ?? new Uint8Array(),
        )
      )
        throw new Error("exact bytes");
    });
  });
}
