// LFCP-039a follow-up: a Key Epoch that puts OUR OWN merged units beyond
// its cutoff takes them out of the replica (G-EP7), not just out of the
// send queue. The handler learns which change each own unit carries when
// the unit is created (recordLocal through createQueuedDataUnit's
// onCreated), and that reference survives in the checkpoint written in
// the same commit. Later local changes that build on an excluded one go
// with it, and the replica refuses to write again under sequences already
// used (§9 minSeq).

import {
  createQueuedDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
  OutboundQueue,
  ProfileCheckpointer,
} from "@openlfcp/client";
import { type DataUnitId, dataEpoch, type ObjectId, resourceId } from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
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
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import {
  principalDescriptorFromKeys,
  rotateEpoch,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const OWNER: Signer = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};
const R = resourceId(bytes32(210));
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;

describe("own units under G-EP7", () => {
  it("leave the replica when a new Key Epoch cuts them off, with their dependents, and §9 blocks reuse", async () => {
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
    const chain = validateControlChain([genesis.bytes]);
    if (chain.kind !== "linear") throw new Error(chain.kind);
    const storage = new InMemoryLfcpStorage();
    const { replica, change: init } = SharedObjectsReplica.create({
      resource: R,
      principal: OWNER.descriptor.principalId,
    });
    const profile = new SharedObjectsDataProfile(replica);
    const checkpoints = new ProfileCheckpointer(storage, profile, { minIntervalMs: 0 });
    const handler: DataProfileHandler<CheckedChange> = {
      dataProfile: profile.dataProfile,
      codecFor: (u) => profile.codecFor(u),
      apply: (u, v) => profile.apply(u, v),
      exclude: (ids) => profile.exclude(ids),
    };
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [handler as DataProfileHandler<unknown>],
    });
    const units: DataUnitId[] = [];
    const write = async (local: LocalChange) => {
      const u = await createQueuedDataUnit(
        storage,
        {
          view: chain,
          controlHead: chain.state.head,
          actor: OWNER,
          dek: DEK0,
          profile: profile.codecFor({ resourceId: R, actor: OWNER.descriptor.principalId }),
          previousUnitId: units.at(-1) ?? null,
          value: checkChange(local.change),
          onCreated: (created, value) => profile.recordLocal(created.unitId, value),
        },
        () => [checkpoints.write()], // the checkpoint, with the new reference, in the same commit
      );
      units.push(u.unitId);
    };
    const task = () => profile.replica.task(TASK)?.task as Task;

    await write(init); // seq 1
    await write(
      profile.replica.apply(
        createTask({ id: TASK, title: "Draft", createdBy: OWNER.descriptor.principalId }).intent,
      ) as LocalChange,
    ); // 2
    await write(profile.replica.apply(setTitle(task(), "Final").intent) as LocalChange); // 3
    await write(profile.replica.apply(setStatus(task(), "done").intent) as LocalChange); // 4, builds on 3
    expect(task()).toMatchObject({ title: "Final", status: "done" });
    expect((await storage.profileState.checkpoint(R))?.units).toHaveLength(4);

    // A Key Epoch closes epoch 0 with our frontier at sequence 2.
    const rotation = rotateEpoch(chain.state, OWNER, {
      reason: 1n,
      finalFrontier: [{ principalId: OWNER.descriptor.principalId, contiguous: 2n, extras: [] }],
      dek: DEK1,
    });
    const next = validateControlChain([genesis.bytes, rotation.bytes]);
    if (next.kind !== "linear") throw new Error(next.kind);
    const outbound = new OutboundQueue({ storage });
    const stale = await outbound.reconcileEpochs(next);
    const applied = await applier.reconcileEpochs(next);

    expect(stale.map((s) => s.seq)).toEqual([3n, 4n]);
    expect(applied.excluded.map((e) => e.unitId)).toEqual([units[2], units[3]]);
    // The replica no longer holds the cut-off changes: the Task is back to its state at sequence 2.
    expect(task()).toMatchObject({ title: "Draft", status: "todo" });
    expect(profile.replica.writable).toBe(false); // sequences 3 and 4 were used (§9)
    expect(() => profile.replica.apply(setTitle(task(), "again").intent)).toThrow(
      expect.objectContaining({ code: "SEQUENCE_REUSE" }),
    );
    expect((await storage.dataUnits.get(units[2] as DataUnitId))?.status).toBe("quarantined");

    // The reference also survives a restart: restore from the checkpoint written with the units.
    const restored = SharedObjectsDataProfile.restore(
      (await storage.profileState.checkpoint(R)) as never,
      {
        resource: R,
        principal: OWNER.descriptor.principalId,
      },
    );
    expect(restored.exclude([units[3] as DataUnitId]).objects).toEqual([TASK]);
    expect(restored.replica.task(TASK)?.task).toMatchObject({ title: "Final", status: "todo" });
  });
});
