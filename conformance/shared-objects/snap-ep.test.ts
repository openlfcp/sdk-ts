// PROVISIONAL (SNAP-EP): a Key Epoch learned AFTER a Snapshot was loaded,
// whose cutoff falls inside the Snapshot's frontier. The client drops the
// Snapshot-derived state, rebuilds the profile from accepted units only,
// fetches the covered units again, and G-EP7 applies normally: the unit
// beyond the cutoff stays out.

import { createQueuedDataUnit, type DataProfileHandler, DataUnitApplier } from "@openlfcp/client";
import { type DataUnitId, dataEpoch, hash32, type ObjectId, resourceId } from "@openlfcp/core";
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
  canonicalFrontierToCbor,
  principalDescriptorFromKeys,
  rotateEpoch,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { encode } from "@openlfcp/wire/cbor";
import { describe, expect, it } from "vitest";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = importSigningKey(bytes32(1));
const OWNER: Signer = {
  key,
  descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(101))),
};
const READER = principalDescriptorFromKeys(
  importSigningKey(bytes32(41)),
  importAgreementKey(bytes32(141)),
).principalId;
const R = resourceId(bytes32(230));
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;

const handlerOf = (profile: SharedObjectsDataProfile): DataProfileHandler<CheckedChange> => ({
  dataProfile: profile.dataProfile,
  codecFor: (u) => profile.codecFor(u),
  apply: (u, v) => profile.apply(u, v),
  exclude: (ids) => profile.exclude(ids),
  has: (id) => profile.has(id),
  reset: () => profile.reset(),
});

describe("SNAP-EP: a later Key Epoch cuts inside a loaded Snapshot", () => {
  it("drops the Snapshot state, rebuilds from accepted units, and keeps the cut-off unit out", async () => {
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
    const view = validateControlChain([genesis.bytes]);
    if (view.kind !== "linear") throw new Error(view.kind);

    // OWNER writes four units; a Snapshot is taken after the third.
    const ownerStorage = new InMemoryLfcpStorage();
    const { replica, change: init } = SharedObjectsReplica.create({
      resource: R,
      principal: OWNER.descriptor.principalId,
    });
    const owner = new SharedObjectsDataProfile(replica);
    const units: { bytes: Uint8Array; unitId: DataUnitId }[] = [];
    const changes: Uint8Array[] = [];
    const task = (p: SharedObjectsDataProfile) => p.replica.task(TASK)?.task as Task;
    let snapshotSave: Uint8Array = new Uint8Array();
    for (const make of [
      () => init,
      () =>
        owner.replica.apply(
          createTask({ id: TASK, title: "Draft", createdBy: OWNER.descriptor.principalId }).intent,
        ),
      () => owner.replica.apply(setTitle(task(owner), "Third").intent),
      () => owner.replica.apply(setStatus(task(owner), "done").intent),
    ]) {
      const local = make() as LocalChange;
      changes.push(local.change);
      units.push(
        await createQueuedDataUnit(ownerStorage, {
          view,
          controlHead: view.state.head,
          actor: OWNER,
          dek: DEK0,
          profile: owner.codecFor({ resourceId: R, actor: OWNER.descriptor.principalId }),
          previousUnitId: units.at(-1)?.unitId ?? null,
          value: checkChange(local.change),
        }),
      );
      if (units.length === 3) snapshotSave = owner.snapshotState();
    }

    // A reader loads the Snapshot (frontier OWNER 1..3), accepts unit 3 as covered and merges unit 4.
    const storage = new InMemoryLfcpStorage();
    const reader = new SharedObjectsDataProfile(
      SharedObjectsReplica.empty({ resource: R, principal: READER }),
    );
    const applier = new DataUnitApplier({
      storage,
      dek: () => DEK0,
      handlers: [handlerOf(reader) as DataProfileHandler<unknown>],
    });
    reader.loadSnapshot(snapshotSave);
    await storage.commit([
      {
        op: "put-snapshot",
        row: {
          snapshotId: hash32(bytes32(7)),
          resourceId: R,
          dataEpoch: dataEpoch(0n),
          publisher: OWNER.descriptor.principalId,
          snapshotSeq: 1n,
          frontier: encode(
            canonicalFrontierToCbor([
              { principalId: OWNER.descriptor.principalId, contiguous: 3n, extras: [] },
            ]),
          ),
          bytes: Uint8Array.of(0xd2),
        },
      },
    ]);
    expect(await applier.acceptCovered(view, units[2]?.bytes as Uint8Array)).toMatchObject({
      kind: "covered",
    });
    expect(await applier.receive(view, units[3]?.bytes as Uint8Array)).toMatchObject({
      kind: "applied",
    });
    expect(task(reader)).toMatchObject({ title: "Third", status: "done" });

    // A Key Epoch closes epoch 0 with OWNER's frontier at 2: inside the Snapshot.
    const rotation = rotateEpoch(view.state, OWNER, {
      reason: 1n,
      finalFrontier: [{ principalId: OWNER.descriptor.principalId, contiguous: 2n, extras: [] }],
      dek: DEK1,
    });
    const next = validateControlChain([genesis.bytes, rotation.bytes]);
    if (next.kind !== "linear") throw new Error(next.kind);
    const r = await applier.reconcileEpochs(next);
    expect(r.snapshotDropped).toBe(true);
    expect(r.excluded.map((e) => e.unitId)).toEqual([units[3]?.unitId]);
    expect(await storage.snapshots.list(R)).toEqual([]);
    expect(await storage.dataUnits.get(units[2]?.unitId as DataUnitId)).toMatchObject({
      status: "seen",
      accepted: false,
    });
    expect(reader.replica.objectIds()).toEqual([]); // nothing accepted survives on its own yet

    // The covered units are fetched again; unit 3 is now beyond the cutoff.
    for (const u of units.slice(0, 3)) await applier.receive(next, u.bytes);
    expect((await storage.dataUnits.get(units[2]?.unitId as DataUnitId))?.status).toBe(
      "quarantined",
    );
    const atTwo = SharedObjectsReplica.fromChanges(changes.slice(0, 2), {
      resource: R,
      principal: READER,
    }).replica;
    expect(reader.replica.root()).toEqual(atTwo.root());
    expect(task(reader)).toMatchObject({ title: "Draft", status: "todo" });
  });
});
