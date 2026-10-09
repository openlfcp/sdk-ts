// LFCP-02-030: the SDK's persistence and status contract under injected
// faults, on SQLite and a file key store (isolated temporary directories).
// A full disk or a write error at the commit's durable boundary, and a key
// store that cannot be read, never yield a saved-local claim, a receipt or
// a status for the failed batch, and nothing is reset to recover: the
// retry under the same operation commits once. An offline durable batch is
// pending (SI03) across a restart, under the same receipt. The other fault
// points of the test plan (§8) are covered where docs/devel/reports/
// sdk-fault-qualification.md (.github) lists them.

import {
  type CommitBinding,
  type DataProfileHandler,
  DataUnitApplier,
  dekResolver,
  NotWritableError,
  OutboundQueue,
  receiptOf,
  releaseReceipt,
  type StatusEvent,
  SyncClient,
  saveControlChain,
} from "@openlfcp/client";
import { dataEpoch, type ResourceId, resourceId } from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import {
  SECTIONS_PROFILE_ID,
  type SectionIntent,
  SectionReplica,
  SharedSectionsDataProfile,
} from "@openlfcp/shared-objects/sections";
import { dekSecretRef, type EpochRow, type LfcpStorage, type SecretStore } from "@openlfcp/storage";
import { FileSecretStore, SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  principalDescriptorFromKeys,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { inDir, makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const KEY = importSigningKey(bytes32(1));
const AGREEMENT = importAgreementKey(bytes32(101));
const OWNER = { key: KEY, descriptor: principalDescriptorFromKeys(KEY, AGREEMENT) };
const me = OWNER.descriptor.principalId;
const DEK0 = importResourceDEK(bytes32(150));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const create: SectionIntent = {
  intent: "section.create",
  sectionId: SECTION,
  title: "S",
  createdBy: me,
};
const item = (n: number): SectionIntent => ({
  intent: "item.create",
  id: id(n),
  parent: SECTION,
  after: null,
  text: `item ${n}`,
  createdBy: me,
});

/** A storage whose commit fails while `failing` is set, as a full disk does. */
function faultyStorage(inner: LfcpStorage) {
  const fault = { failing: false };
  const storage = new Proxy(inner, {
    get(target, prop) {
      if (prop === "commit")
        return async (writes: Parameters<LfcpStorage["commit"]>[0]) => {
          if (fault.failing) throw new Error("SQLITE_FULL: database or disk is full");
          return target.commit(writes);
        };
      const v = Reflect.get(target, prop, target);
      return typeof v === "function" ? v.bind(target) : v;
    },
  });
  return { storage, fault };
}

/** A key store that cannot be read or written while `down` is set. */
function faultySecrets(inner: SecretStore) {
  const fault = { down: false };
  const check = () => {
    if (fault.down) throw new Error("the key store is unavailable");
  };
  const secrets: SecretStore = {
    get: async (ref) => {
      check();
      return inner.get(ref);
    },
    put: async (ref, bytes) => {
      check();
      return inner.put(ref, bytes);
    },
    delete: async (ref) => {
      check();
      return inner.delete(ref);
    },
  };

  return { secrets, fault };
}

/** One device on SQLite in `dir`: a section Resource of OWNER, offline. */
async function device(dir: string) {
  const R: ResourceId = resourceId(bytes32(200));
  const sqlite = SqliteLfcpStorage.open(inDir(dir, "lfcp.sqlite"));
  const { storage, fault } = faultyStorage(sqlite);
  const files = faultySecrets(new FileSecretStore(inDir(dir, "secrets")));
  const secrets = files.secrets;
  if ((await storage.control.head(R)) === undefined) {
    const genesis = signControlRecord(
      { resourceId: R, controlSeq: 0n, prevControlId: null },
      {
        type: "GENESIS",
        dataProfile: SECTIONS_PROFILE_ID,
        owner: OWNER.descriptor,
        dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
        endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
        coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
      },
      OWNER,
    );
    const view = validateControlChain([genesis.bytes]);
    if (view.kind !== "linear") throw new Error(view.kind);
    await saveControlChain(storage, view, null);
    const ref = dekSecretRef(R, dataEpoch(0n));
    await secrets.put(ref, exportSecretKeyBytes(DEK0));
    const e0 = (await storage.control.epochs(R))[0] as EpochRow;
    await storage.commit([{ op: "put-epoch", resourceId: R, epoch: { ...e0, dekRef: ref } }]);
  }
  const checkpoint = await storage.profileState.checkpoint(R);
  const profile =
    checkpoint === undefined
      ? new SharedSectionsDataProfile(SectionReplica.empty({ resource: R, principal: me }))
      : SharedSectionsDataProfile.restore(checkpoint as never, { resource: R, principal: me });
  const handler: DataProfileHandler<unknown> = {
    dataProfile: profile.dataProfile,
    codecFor: (u) => profile.codecFor(u) as never,
    apply: (u, v) => profile.apply(u, v as never),
    exclude: (ids) => profile.exclude(ids),
  };
  const sync = new SyncClient({
    url: "ws://127.0.0.1:1/v1/ws",
    signer: OWNER,
    agreement: AGREEMENT,
    storage,
    secrets,
    outbound: new OutboundQueue({ storage }),
    now: () => 0,
  });
  const events: StatusEvent[] = [];
  sync.on((e) => {
    if (e.type === "status") events.push(e.event);
  });
  sync.open({
    resourceId: R,
    applier: new DataUnitApplier({
      storage,
      dek: dekResolver(storage, secrets, R),
      handlers: [handler],
    }),
    commit: profile.commitBinding(me) as CommitBinding<unknown>,
  });
  const close = async () => {
    await sync.stop();
    sqlite.close();
  };
  return { R, storage, secrets, profile, sync, events, fault, keys: files.fault, close };
}

const inTemp = async (body: (dir: string) => Promise<void>) => {
  const dir = makeTempDir("lfcp-faults-");
  try {
    await body(dir);
  } finally {
    removeTempDir(dir);
  }
};

describe("SDK faults at the durable boundary (LFCP-02-030)", () => {
  it("a full disk at commit: no receipt, no status, nothing reset; the retry commits once (SI17)", () =>
    inTemp(async (dir) => {
      const d = await device(dir);
      await d.sync.commit(d.R, [create], { operationId: "op-1" });
      const queued = await d.storage.outbound.list(d.R);
      const revision = d.profile.replica.revision();
      const events = d.events.length;

      d.fault.failing = true;
      await expect(d.sync.commit(d.R, [item(10)], { operationId: "op-2" })).rejects.toThrow(
        "SQLITE_FULL",
      );
      // Nothing claims the batch: no receipt, no batch event, no status row.
      expect(await receiptOf(d.storage, d.R, "op-2")).toBeUndefined();
      expect(d.events.slice(events).filter((e) => e.kind === "batch")).toEqual([]);
      expect((await d.sync.statusSnapshot(d.R)).batches.map((b) => b.operationId)).toEqual([
        "op-1",
      ]);
      // The model and the queue are as before: nothing half applied, nothing purged.
      expect(d.profile.replica.revision()).toBe(revision);
      expect(await d.storage.outbound.list(d.R)).toEqual(queued);

      // The disk has room again: the same operation commits once.
      d.fault.failing = false;
      const r = await d.sync.commit(d.R, [item(10)], { operationId: "op-2" });
      expect(await d.sync.commit(d.R, [item(10)], { operationId: "op-2" })).toEqual(r);
      const after = await d.storage.outbound.list(d.R);
      expect(after.slice(0, queued.length)).toEqual(queued);
      expect(after).toHaveLength(queued.length + 1);
      const seqs = await Promise.all(
        after.map(async (q) => (await d.storage.dataUnits.get(q.itemId as never))?.actorSeq),
      );
      expect(new Set(seqs.map(String)).size).toBe(seqs.length);
      expect(d.profile.replica.snapshot().nodes[id(10)]?.text).toBe("item 10");
      await d.close();
    }));

  it("an unavailable key store: key-unavailable, nothing written, no key or state purged", () =>
    inTemp(async (dir) => {
      const d = await device(dir);
      await d.sync.commit(d.R, [create], { operationId: "op-1" });
      d.keys.down = true;
      expect(await d.sync.accessState(d.R)).toMatchObject({
        allowed: false,
        reason: "key-unavailable",
      });
      const refused = d.sync.commit(d.R, [item(11)], { operationId: "op-2" });
      await expect(refused).rejects.toBeInstanceOf(NotWritableError);
      await expect(refused).rejects.toMatchObject({ access: { reason: "key-unavailable" } });
      expect(await receiptOf(d.storage, d.R, "op-2")).toBeUndefined();
      // The key store is back: the key and its reference are still there.
      d.keys.down = false;
      const row = (await d.storage.control.epochs(d.R))[0];
      expect(row?.dekRef).toBe(dekSecretRef(d.R, dataEpoch(0n)));
      expect(await d.sync.accessState(d.R)).toMatchObject({ allowed: true });
      await d.sync.commit(d.R, [item(11)], { operationId: "op-2" });
      expect((await d.sync.statusSnapshot(d.R)).batches.map((b) => b.status)).toEqual([
        "pending",
        "pending",
      ]);
      await d.close();
    }));

  it("an offline durable batch is pending, and stays so under the same receipt after a restart (SI03)", () =>
    inTemp(async (dir) => {
      const first = await device(dir);
      const receipt = await first.sync.commit(first.R, [create, item(12)], {
        operationId: "op-1",
      });
      const snap = await first.sync.statusSnapshot(first.R);
      expect(snap.batches).toMatchObject([
        { operationId: "op-1", status: "pending", acceptedUnitIds: [] },
      ]);
      expect(snap.catchUp.state).toBe("not-started");
      const queued = await first.storage.outbound.list(first.R);
      await first.close();

      // The process is gone; a new one opens the same files.
      const second = await device(dir);
      expect(await receiptOf(second.storage, second.R, "op-1")).toEqual(receipt);
      expect(await second.storage.outbound.list(second.R)).toEqual(queued);
      expect((await second.sync.statusSnapshot(second.R)).batches).toMatchObject([
        { operationId: "op-1", status: "pending" },
      ]);
      // A retry after the uncertain end of the first process adds nothing.
      expect(
        await second.sync.commit(second.R, [create, item(12)], { operationId: "op-1" }),
      ).toEqual(receipt);
      expect(await second.storage.outbound.list(second.R)).toEqual(queued);
      expect(second.profile.replica.snapshot().nodes[id(12)]?.text).toBe("item 12");
      await second.close();
    }));

  it("after a restart with the server unreachable, a queued batch stays pending while the client tries (SI03, SI06)", () =>
    inTemp(async (dir) => {
      const first = await device(dir);
      await first.sync.commit(first.R, [create, item(12)], { operationId: "op-1" });
      await first.close();

      const second = await device(dir);
      second.sync.start();
      // A few connection attempts fail (nothing listens on the endpoint).
      await new Promise((r) => setTimeout(r, 1_500));
      expect(await second.storage.outbound.list(second.R)).not.toEqual([]);
      const snap = await second.sync.statusSnapshot(second.R);
      expect(snap.batches).toMatchObject([
        { operationId: "op-1", status: "pending", acceptedUnitIds: [] },
      ]);
      expect(snap.catchUp.state).not.toBe("current");
      expect(second.events.filter((e) => e.kind === "batch" && e.status === "accepted")).toEqual(
        [],
      );
      await second.close();
    }));

  it("a batch released by the adapter before its acceptance stays pending across a restart (SI03, §3.5)", () =>
    inTemp(async (dir) => {
      const first = await device(dir);
      await first.sync.commit(first.R, [create, item(12)], { operationId: "op-1" });
      // The plugin's journal finishes the operation once it is projected.
      await releaseReceipt(first.storage, first.R, "op-1");
      await first.close();

      const second = await device(dir);
      second.sync.start();
      await new Promise((r) => setTimeout(r, 1_500));
      expect(await receiptOf(second.storage, second.R, "op-1")).toBeUndefined();
      expect((await second.sync.statusSnapshot(second.R)).batches).toMatchObject([
        { operationId: "op-1", status: "pending", acceptedUnitIds: [] },
      ]);
      await second.close();
    }));
});
