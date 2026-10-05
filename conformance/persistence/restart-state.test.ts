// LFCP-038: what a client needs after a restart, on the Node adapter
// (SqliteLfcpStorage + FileSecretStore). A "restart" closes the database
// and builds every object again from the same files: fresh storage,
// secret store, profile and applier; no object of the first session is
// reused. (crash-points.test.ts runs the sequence-safety cases in separate
// processes.) Exact bytes of Control Records, Data Units, Key Packages and
// Snapshots across a reopen are part of the storage contract suite, which
// runs on this adapter too.

import {
  createQueuedDataUnit,
  createQueuedSnapshot,
  type DataProfileHandler,
  DataUnitApplier,
  dekResolver,
  loadControlChain,
  ProfileCheckpointer,
  saveControlChain,
} from "@openlfcp/client";
import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  type ObjectId,
  resourceId,
} from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  type ResourceDEK,
} from "@openlfcp/crypto";
import {
  type CheckedChange,
  checkChange,
  createTask,
  type LocalChange,
  PROFILE_ID,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setStatus,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  type LfcpStorage,
} from "@openlfcp/storage";
import { FileSecretStore, SqliteLfcpStorage } from "@openlfcp/storage-node";
import {
  type ChainResult,
  principalDescriptorFromKeys,
  rotateEpoch,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import { inDir, makeTempDir, removeTempDir } from "../storage/temp-dir.mjs";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const BOB = signer(41);
const READER = signer(81).descriptor.principalId;
const R = resourceId(bytes32(250));
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
type Linear = Extract<ChainResult, { kind: "linear" }>;

/** The Resource: Genesis by OWNER, BOB granted read and write. */
const genesis = signControlRecord(
  { resourceId: R, controlSeq: 0n, prevControlId: null },
  {
    type: "GENESIS",
    dataProfile: PROFILE_ID,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
    coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
  },
  OWNER,
);
const grant = signControlRecord(
  { resourceId: R, controlSeq: 1n, prevControlId: genesis.recordId },
  { type: "CAPABILITY_GRANT", subject: BOB.descriptor, abilities: [1n, 2n, 3n], delegable: [] },
  OWNER,
);
const linear = (records: readonly Uint8Array[]): Linear => {
  const r = validateControlChain(records);
  if (r.kind !== "linear") throw new Error(r.kind);
  return r;
};
const VIEW = linear([genesis.bytes, grant.bytes]);

/** A session on the files in `dir`: everything built fresh. */
function session(dir: string) {
  const storage = SqliteLfcpStorage.open(inDir(dir, "lfcp.sqlite"));
  const secrets = new FileSecretStore(inDir(dir, "secrets"));
  return { storage, secrets };
}

async function holdDek(
  storage: LfcpStorage,
  secrets: FileSecretStore,
  epoch: bigint,
  dek: ResourceDEK,
) {
  const ref = dekSecretRef(R, dataEpoch(epoch));
  await secrets.put(ref, exportSecretKeyBytes(dek));
  const row = (await storage.control.epochs(R)).find((e) => e.epoch === epoch) as EpochRow;
  await storage.commit([{ op: "put-epoch", resourceId: R, epoch: { ...row, dekRef: ref } }]);
}

const handlerOf = (profile: SharedObjectsDataProfile): DataProfileHandler<CheckedChange> => ({
  dataProfile: profile.dataProfile,
  codecFor: (u) => profile.codecFor(u),
  apply: (u, v) => profile.apply(u, v),
  exclude: (ids) => profile.exclude(ids),
  has: (id) => profile.has(id),
  reset: () => profile.reset(),
});

/** Two writers producing real units: OWNER creates a Task, then OWNER and BOB edit it concurrently. */
async function writers() {
  const ownerStore = new InMemoryLfcpStorage();
  const bobStore = new InMemoryLfcpStorage();
  const { replica, change: init } = SharedObjectsReplica.create({
    resource: R,
    principal: OWNER.descriptor.principalId,
  });
  const owner = new SharedObjectsDataProfile(replica);
  const unit = async (
    store: LfcpStorage,
    who: Signer,
    profile: SharedObjectsDataProfile,
    local: LocalChange,
    prev: DataUnitId | null,
  ) =>
    createQueuedDataUnit(store, {
      view: VIEW,
      controlHead: VIEW.state.head,
      actor: who,
      dek: DEK0,
      profile: profile.codecFor({ resourceId: R, actor: who.descriptor.principalId }),
      previousUnitId: prev,
      value: checkChange(local.change),
    });
  const task = (p: SharedObjectsDataProfile) => p.replica.task(TASK)?.task as Task;
  const o1 = await unit(ownerStore, OWNER, owner, init, null);
  const o2 = await unit(
    ownerStore,
    OWNER,
    owner,
    owner.replica.apply(
      createTask({ id: TASK, title: "Draft", createdBy: OWNER.descriptor.principalId }).intent,
    ) as LocalChange,
    o1.unitId,
  );
  const bob = new SharedObjectsDataProfile(
    SharedObjectsReplica.fromChanges(owner.replica.changes(), {
      resource: R,
      principal: BOB.descriptor.principalId,
    }).replica,
  );
  const o3 = await unit(
    ownerStore,
    OWNER,
    owner,
    owner.replica.apply(setStatus(task(owner), "done").intent) as LocalChange,
    o2.unitId,
  );
  const b1 = await unit(
    bobStore,
    BOB,
    bob,
    bob.replica.apply(setStatus(task(bob), "cancelled").intent) as LocalChange,
    null,
  );
  const b2 = await unit(
    bobStore,
    BOB,
    bob,
    bob.replica.apply(setTitle(task(bob), "Final").intent) as LocalChange,
    b1.unitId,
  );
  return { o1, o2, o3, b1, b2 };
}

describe("LFCP-038 restart recovery (SQLite + file secrets)", () => {
  it("keeps the Control Head and fails closed on an inconsistent one", async () => {
    const dir = makeTempDir("lfcp-038-control-");
    try {
      let s = session(dir);
      await saveControlChain(s.storage, linear([genesis.bytes]), null);
      await saveControlChain(s.storage, VIEW, genesis.recordId);
      s.storage.close();
      s = session(dir);
      const loaded = await loadControlChain(s.storage, R);
      expect(loaded?.kind === "linear" && [loaded.state.seq, loaded.state.head]).toEqual([
        1n,
        grant.recordId,
      ]);
      // Local corruption: a head that its records do not reach is refused, never replaced by an older one.
      await s.storage.commit([
        {
          op: "set-control-head",
          resourceId: R,
          expected: grant.recordId,
          head: { head: grant.recordId, controlSeq: 7n },
        },
      ]);
      await expect(loadControlChain(s.storage, R)).rejects.toMatchObject({
        code: "INVALID_CONTROL_CHAIN",
      });
      await s.storage.commit([
        {
          op: "set-control-head",
          resourceId: R,
          expected: grant.recordId,
          head: { head: bytes32(66) as ControlRecordId, controlSeq: 2n },
        },
      ]);
      await expect(loadControlChain(s.storage, R)).rejects.toMatchObject({
        code: "INVALID_CONTROL_CHAIN",
      });
      s.storage.close();
    } finally {
      removeTempDir(dir);
    }
  });

  it("recovers epochs and DEK references through the secret store, and fails closed without the secret", async () => {
    const dir = makeTempDir("lfcp-038-keys-");
    try {
      let s = session(dir);
      await saveControlChain(s.storage, VIEW, null);
      await holdDek(s.storage, s.secrets, 0n, DEK0);
      s.storage.close();
      s = session(dir);
      const epochs = await s.storage.control.epochs(R);
      expect(epochs.map((e) => [e.epoch, e.dekRef])).toEqual([
        [0n, dekSecretRef(R, dataEpoch(0n))],
      ]);
      // Derived behavior, never a secret dump: the DEK resolves and seals a unit the commitment accepts.
      const dek = await dekResolver(s.storage, s.secrets, R)(dataEpoch(0n));
      expect(dek).toBeDefined();
      const u = await createQueuedDataUnit(s.storage, {
        view: VIEW,
        controlHead: VIEW.state.head,
        actor: OWNER,
        dek: dek as ResourceDEK,
        profile: { dataProfile: PROFILE_ID, encode: () => Uint8Array.of(1), decode: () => 1 },
        previousUnitId: null,
        value: 1,
      });
      expect(u.seq).toBe(1n);
      // The secret file is gone: no DEK, so nothing can be sealed or opened for that epoch.
      await s.secrets.delete(dekSecretRef(R, dataEpoch(0n)));
      expect(await dekResolver(s.storage, s.secrets, R)(dataEpoch(0n))).toBeUndefined();
      s.storage.close();
    } finally {
      removeTempDir(dir);
    }
  });

  it("keeps held and quarantined units across a restart and resolves them then", async () => {
    const dir = makeTempDir("lfcp-038-held-");
    try {
      const { o1, o2, o3 } = await writers();
      const rotation = rotateEpoch(VIEW.state, OWNER, {
        reason: 1n,
        finalFrontier: [{ principalId: OWNER.descriptor.principalId, contiguous: 2n, extras: [] }],
        dek: DEK1,
      });
      const rotated = linear([genesis.bytes, grant.bytes, rotation.bytes]);
      let s = session(dir);
      await saveControlChain(s.storage, rotated, null);
      let profile = new SharedObjectsDataProfile(
        SharedObjectsReplica.empty({ resource: R, principal: READER }),
      );
      let applier = new DataUnitApplier({
        storage: s.storage,
        dek: () => DEK0,
        handlers: [handlerOf(profile) as DataProfileHandler<unknown>],
      });
      expect(await applier.receive(rotated, o2.bytes)).toMatchObject({
        kind: "held",
        reason: "GAP",
      });
      expect(await applier.receive(rotated, o3.bytes)).toMatchObject({
        kind: "quarantined",
        reason: "BEYOND_CUTOFF",
      });
      s.storage.close();

      s = session(dir);
      expect((await s.storage.dataUnits.get(o2.unitId))?.status).toBe("held");
      expect((await s.storage.dataUnits.get(o3.unitId))?.status).toBe("quarantined");
      profile = new SharedObjectsDataProfile(
        SharedObjectsReplica.empty({ resource: R, principal: READER }),
      );
      applier = new DataUnitApplier({
        storage: s.storage,
        dek: () => DEK0,
        handlers: [handlerOf(profile) as DataProfileHandler<unknown>],
      });
      const first = await applier.receive(rotated, o1.bytes);
      expect(first.kind === "applied" && first.released.map((r) => r.kind)).toEqual(["applied"]);
      expect(await applier.receive(rotated, o3.bytes)).toMatchObject({ kind: "quarantined" });
      expect(profile.replica.task(TASK)?.task?.status).toBe("todo");
      s.storage.close();
    } finally {
      removeTempDir(dir);
    }
  });

  it("reconstructs the replica from its checkpoint plus the units merged after it, conflicts included", async () => {
    const dir = makeTempDir("lfcp-038-crdt-");
    try {
      const { o1, o2, o3, b1, b2 } = await writers();
      let s = session(dir);
      await saveControlChain(s.storage, VIEW, null);
      await holdDek(s.storage, s.secrets, 0n, DEK0);
      let profile = new SharedObjectsDataProfile(
        SharedObjectsReplica.empty({ resource: R, principal: READER }),
      );
      let applier = new DataUnitApplier({
        storage: s.storage,
        dek: dekResolver(s.storage, s.secrets, R),
        handlers: [handlerOf(profile) as DataProfileHandler<unknown>],
      });
      for (const u of [o1, o2]) await applier.receive(VIEW, u.bytes);
      await new ProfileCheckpointer(s.storage, profile, { minIntervalMs: 0 }).flush(0); // checkpoint after o2
      for (const u of [o3, b1, b2]) await applier.receive(VIEW, u.bytes); // merged after the checkpoint
      const before = { root: profile.replica.root(), conflicts: profile.replica.conflicts() };
      expect(before.conflicts).toEqual({ [TASK]: { status: ["cancelled", "done"] } });
      s.storage.close();

      // Restart: restore the checkpoint, then replay the stored units it lacks.
      s = session(dir);
      const cp = await s.storage.profileState.checkpoint(R);
      profile = SharedObjectsDataProfile.restore(cp as never, { resource: R, principal: READER });
      applier = new DataUnitApplier({
        storage: s.storage,
        dek: dekResolver(s.storage, s.secrets, R),
        handlers: [handlerOf(profile) as DataProfileHandler<unknown>],
      });
      const replay = await applier.replayStored(VIEW);
      expect(replay.replayed.length).toBe(3);
      expect(replay.skipped).toEqual([]);
      expect(profile.replica.root()).toEqual(before.root);
      expect(profile.replica.conflicts()).toEqual(before.conflicts);
      // Nothing is applied twice: a replay or a re-delivery changes nothing.
      expect((await applier.replayStored(VIEW)).replayed).toEqual([]);
      expect(await applier.receive(VIEW, b2.bytes)).toMatchObject({ kind: "duplicate" });

      // G-EP7 after the restart: a newly learned Key Epoch still excludes correctly.
      const rotation = rotateEpoch(VIEW.state, OWNER, {
        reason: 1n,
        finalFrontier: [
          { principalId: OWNER.descriptor.principalId, contiguous: 3n, extras: [] },
          { principalId: BOB.descriptor.principalId, contiguous: 1n, extras: [] },
        ],
        dek: DEK1,
      });
      const r = await applier.reconcileEpochs(linear([genesis.bytes, grant.bytes, rotation.bytes]));
      expect(r.excluded.map((e) => e.unitId)).toEqual([b2.unitId]);
      expect(profile.replica.task(TASK)?.task?.title).toBe("Draft");
      expect(profile.replica.conflicts()).toEqual(before.conflicts);
      s.storage.close();
    } finally {
      removeTempDir(dir);
    }
  });

  it("fails closed on a corrupt checkpoint", async () => {
    const dir = makeTempDir("lfcp-038-corrupt-");
    try {
      const s = session(dir);
      await s.storage.commit([
        {
          op: "put-profile-checkpoint",
          checkpoint: {
            resourceId: R,
            dataProfile: PROFILE_ID,
            state: Uint8Array.of(1, 2, 3),
            actorSeq: 0,
            units: [],
          },
        },
      ]);
      const cp = await s.storage.profileState.checkpoint(R);
      expect(() =>
        SharedObjectsDataProfile.restore(cp as never, { resource: R, principal: READER }),
      ).toThrow(
        expect.objectContaining({ code: "PROFILE_INVALID", diagnostic: "INVALID_AUTOMERGE_BYTES" }),
      );
      s.storage.close();
    } finally {
      removeTempDir(dir);
    }
  });

  it("continues Snapshot Sequences across a restart", async () => {
    const dir = makeTempDir("lfcp-038-snapshot-");
    try {
      const publish = async (s: ReturnType<typeof session>) =>
        createQueuedSnapshot(s.storage, {
          view: VIEW,
          controlHead: VIEW.state.head,
          publisher: BOB,
          dek: DEK0,
          frontier: [],
          profile: { dataProfile: PROFILE_ID, encode: () => Uint8Array.of(9), decode: () => 9 },
          value: 9,
        });
      let s = session(dir);
      expect((await publish(s)).seq).toBe(1n);
      s.storage.close();
      s = session(dir);
      const second = await publish(s);
      expect(second.seq).toBe(2n);
      expect((await s.storage.snapshots.get(second.snapshotId))?.bytes).toEqual(second.bytes);
      expect(await s.storage.outbound.list(R)).toHaveLength(2);
      s.storage.close();
    } finally {
      removeTempDir(dir);
    }
  });
});
