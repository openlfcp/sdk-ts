// LFCP-039a follow-up: a Key Epoch that puts OUR OWN merged units beyond
// its cutoff takes them out of the replica (G-EP7), not just out of the
// send queue. The handler learns which change each own unit carries when
// the unit is created (recordLocal through createQueuedDataUnit's
// onCreated), and that reference survives in the checkpoint written in
// the same commit. Later local changes that build on an excluded one go
// with it. Removed own changes are not lost state (§9, SPEC-PATCH-06 item
// 7): the writer re-applies the stale work under the removed sequence, and
// a receiver that merged the old changes holds the new unit until it
// learns the Key Epoch.

import {
  createQueuedDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
  OutboundQueue,
  ProfileCheckpointer,
} from "@openlfcp/client";
import {
  type DataUnitId,
  dataEpoch,
  type ObjectId,
  principalId,
  resourceId,
  toHex,
} from "@openlfcp/core";
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
  parseDataUnit,
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
const PEER = principalId(bytes32(150));

describe("own units under G-EP7", () => {
  it("leave the replica when a new Key Epoch cuts them off, with their dependents, and the writer re-applies", async () => {
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
    expect((await storage.dataUnits.get(units[2] as DataUnitId))?.status).toBe("quarantined");
    const restoredBefore = (await storage.profileState.checkpoint(R)) as never;

    // §9 (SPEC-PATCH-06 item 7): removed own changes are not lost state. The
    // stale work is re-applied as a new unit in epoch 1 (G-EP5): Automerge
    // sequence 3 again, LFCP sequence 5 naming unit 2 (§26.2).
    expect(profile.replica.writable).toBe(true);
    const again = profile.replica.apply(setTitle(task(), "Final again").intent) as LocalChange;
    expect(again.seq).toBe(3);
    const reapplied = await createQueuedDataUnit(
      storage,
      {
        view: next,
        controlHead: next.state.head,
        actor: OWNER,
        dek: DEK1,
        profile: profile.codecFor({ resourceId: R, actor: OWNER.descriptor.principalId }),
        value: checkChange(again.change),
        onCreated: (created, value) => profile.recordLocal(created.unitId, value),
      },
      () => [checkpoints.write()],
    );
    expect(reapplied.seq).toBe(5n);
    expect(toHex(parseDataUnit(reapplied.bytes).payload.prevDataUnitId as Uint8Array)).toBe(
      toHex(units[1] as DataUnitId),
    );

    // A receiver that merged 1..4 holds the new unit (PREV_MISMATCH) until it
    // learns the Key Epoch, then rebuilds without 3 and 4 and merges it.
    const theirs = new InMemoryLfcpStorage();
    const receiver = new SharedObjectsDataProfile(
      SharedObjectsReplica.empty({ resource: R, principal: PEER }),
    );
    const receiverApplier = new DataUnitApplier({
      storage: theirs,
      dek: (epoch) => (epoch === 0n ? DEK0 : DEK1),
      handlers: [
        {
          dataProfile: receiver.dataProfile,
          codecFor: (u) => receiver.codecFor(u),
          apply: (u, v) => receiver.apply(u, v),
          exclude: (ids) => receiver.exclude(ids),
        } as DataProfileHandler<CheckedChange> as DataProfileHandler<unknown>,
      ],
    });
    for (const id of units) {
      const u = await storage.dataUnits.get(id);
      expect((await receiverApplier.receive(chain, u?.bytes as Uint8Array)).kind).toBe("applied");
    }
    expect(receiver.replica.task(TASK)?.task).toMatchObject({ title: "Final", status: "done" });
    expect(await receiverApplier.receive(next, reapplied.bytes)).toMatchObject({
      kind: "held",
      reason: "PREV_MISMATCH",
    });
    const reconciled = await receiverApplier.reconcileEpochs(next);
    expect(reconciled.excluded.map((e) => e.unitId)).toEqual([units[2], units[3]]);
    expect(reconciled.released.map((x) => x.kind)).toEqual(["applied"]);
    expect(receiver.replica.task(TASK)?.task).toMatchObject({
      title: "Final again",
      status: "todo",
    });
    expect(JSON.stringify(receiver.replica.root())).toBe(JSON.stringify(profile.replica.root()));

    // The reference also survives a restart: restore from the checkpoint written with the units.
    const restored = SharedObjectsDataProfile.restore(restoredBefore, {
      resource: R,
      principal: OWNER.descriptor.principalId,
    });
    expect(restored.exclude([units[3] as DataUnitId]).objects).toEqual([TASK]);
    expect(restored.replica.task(TASK)?.task).toMatchObject({ title: "Final", status: "todo" });
  });
});
