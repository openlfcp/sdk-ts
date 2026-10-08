// SyncClient.commit with the Shared Sections profile (LFCP-02-025,
// SDK-SECTIONS-INTEGRATION-01 §3.1): the facade an editor uses. Offline:
// the client never connects, so what is checked is the local commit — the
// receipt, the queued units, the checkpoint, the idempotent retry and a
// batch split over the change budgets — not the send.

import {
  type CommitBinding,
  type DataProfileHandler,
  DataUnitApplier,
  dekResolver,
  OperationIdReusedError,
  OutboundQueue,
  receiptOf,
  SyncClient,
  saveControlChain,
} from "@openlfcp/client";
import { type ControlRecordId, dataEpoch, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { createTask } from "@openlfcp/shared-objects";
import {
  SECTIONS_PROFILE_ID,
  type SectionIntent,
  SectionReplica,
  SharedSectionsDataProfile,
} from "@openlfcp/shared-objects/sections";
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  InMemorySecretStore,
} from "@openlfcp/storage";
import {
  type ControlBody,
  principalDescriptorFromKeys,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const OWNER_KEY = importSigningKey(bytes32(1));
const OWNER = {
  key: OWNER_KEY,
  descriptor: principalDescriptorFromKeys(OWNER_KEY, importAgreementKey(bytes32(101))),
};
const AGREEMENT = importAgreementKey(bytes32(101));
const DEK0 = importResourceDEK(bytes32(150));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const SECTION = id(1);
const me = OWNER.descriptor.principalId;

async function device() {
  const R = resourceId(bytes32(200));
  const records: Uint8Array[] = [];
  let head: ControlRecordId | null = null;
  const add = (body: ControlBody) => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head },
      body,
      OWNER,
    );
    records.push(s.bytes);
    head = s.recordId;
  };
  add({
    type: "GENESIS",
    dataProfile: SECTIONS_PROFILE_ID,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
    coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
  });
  const view = validateControlChain(records);
  if (view.kind !== "linear") throw new Error(view.kind);
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
  await saveControlChain(storage, view, null);
  await secrets.put(dekSecretRef(R, dataEpoch(0n)), exportSecretKeyBytes(DEK0));
  const e0 = (await storage.control.epochs(R))[0] as EpochRow;
  await storage.commit([
    { op: "put-epoch", resourceId: R, epoch: { ...e0, dekRef: dekSecretRef(R, dataEpoch(0n)) } },
  ]);

  const profile = new SharedSectionsDataProfile(
    SectionReplica.empty({ resource: R, principal: me }),
  );
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
  sync.open({
    resourceId: R,
    applier: new DataUnitApplier({
      storage,
      dek: dekResolver(storage, secrets, R),
      handlers: [handler],
    }),
    commit: profile.commitBinding(me) as CommitBinding<unknown>,
  });
  return { R, storage, profile, sync };
}

const create: SectionIntent = {
  intent: "section.create",
  sectionId: SECTION,
  title: "S",
  createdBy: me,
};
const tasks = (n: number, from = 1000): SectionIntent[] =>
  Array.from({ length: n }, (_, k) => ({
    intent: "task.create_in_section",
    task: createTask({ id: id(from + k) as never, title: `Task ${k}`, createdBy: me }).task,
    parent: SECTION,
    after: null,
  }));

describe("SyncClient.commit with shared sections (§3.1)", () => {
  it("commits a batch durably and returns its receipt", async () => {
    const d = await device();
    const receipt = await d.sync.commit(d.R, [create, ...tasks(2)], { operationId: "op-1" });
    expect(receipt.unitIds).toHaveLength(1);
    expect(receipt.modelRevision).toBe(d.profile.replica.revision());
    expect(await receiptOf(d.storage, d.R, "op-1")).toEqual(receipt);
    expect((await d.storage.outbound.list(d.R)).map((o) => o.kind)).toEqual(["data-unit"]);
    const checkpoint = await d.storage.profileState.checkpoint(d.R);
    expect(checkpoint?.units.map((u) => toHex(u.unitId))).toEqual(
      receipt.unitIds.map((u) => toHex(u)),
    );
    expect(d.profile.replica.snapshot().order).toHaveLength(2);
  });

  it("returns the receipt again for a retry, and refuses other intents under its ID", async () => {
    const d = await device();
    const first = await d.sync.commit(d.R, [create], { operationId: "op-1" });
    expect(await d.sync.commit(d.R, [create], { operationId: "op-1" })).toEqual(first);
    await expect(d.sync.commit(d.R, tasks(1), { operationId: "op-1" })).rejects.toBeInstanceOf(
      OperationIdReusedError,
    );
    expect(d.profile.replica.changes()).toHaveLength(1);
  });

  it("commits a batch over the change budgets as several units with one receipt", async () => {
    const d = await device();
    const receipt = await d.sync.commit(d.R, [create, ...tasks(300)], { operationId: "import" });
    expect(receipt.unitIds).toHaveLength(2);
    expect(await d.storage.outbound.list(d.R)).toHaveLength(2);
    expect(d.profile.replica.validate().state).toBe("ready");
    expect(d.profile.replica.snapshot().order).toHaveLength(300);
  });

  it("refuses a batch the profile refuses, and leaves nothing behind", async () => {
    const d = await device();
    await d.sync.commit(d.R, [create], { operationId: "op-1" });
    const before = d.profile.replica.revision();
    await expect(
      d.sync.commit(d.R, [{ intent: "node.move", id: id(9), parent: SECTION, after: null }], {
        operationId: "op-2",
      }),
    ).rejects.toMatchObject({ code: "UNKNOWN_NODE" });
    expect(d.profile.replica.revision()).toBe(before);
    expect(await receiptOf(d.storage, d.R, "op-2")).toBeUndefined();
  });
});
