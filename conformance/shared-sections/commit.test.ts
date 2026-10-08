// Committing section batches with durable receipts (LFCP-02-025,
// SDK-SECTIONS-INTEGRATION-01 §3): a batch is staged on the replica,
// committed with commitOperation (its Data Unit, outbound entry, profile
// checkpoint and receipt in one storage transaction) and adopted only when
// that succeeds. Crashes before and after the commit, idempotent retries and
// a reused operation ID never duplicate content. Lives here because it uses
// both client and shared-objects, which no package may import together.

import {
  commitOperation,
  type DataProfileHandler,
  DataUnitApplier,
  intentsHash,
  OperationIdReusedError,
  type Receipt,
  receiptOf,
  releaseReceipt,
} from "@openlfcp/client";
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
import { type CheckedChange, checkChange, createTask } from "@openlfcp/shared-objects";
import {
  SECTIONS_PROFILE_ID,
  type SectionIntent,
  SectionReplica,
  SharedSectionsDataProfile,
} from "@openlfcp/shared-objects/sections";
import { InMemoryLfcpStorage, type LfcpStorage } from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";

type View = Extract<ChainResult, { kind: "linear" }>;
const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const signer = (seed: number): Signer => {
  const key = importSigningKey(bytes32(seed));
  return {
    key,
    descriptor: principalDescriptorFromKeys(key, importAgreementKey(bytes32(seed + 100))),
  };
};
const OWNER = signer(1);
const ALICE = signer(33);
const BOB = signer(65);
const DEK0 = importResourceDEK(bytes32(150));
const id = (n: number) => `0192e4a0-0000-7000-8000-${n.toString(16).padStart(12, "0")}`;
const [SECTION, T, P] = [id(1), id(2), id(3)];

/** A section Resource: Genesis with the sections profile, then grants for Alice and Bob. */
function chain(): View {
  const resource = resourceId(bytes32(200));
  const records: Uint8Array[] = [];
  let head: ControlRecordId | null = null;
  const add = (body: ControlBody) => {
    const s = signControlRecord(
      { resourceId: resource, controlSeq: BigInt(records.length), prevControlId: head },
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
    dekCommitment: dekCommitment(resource, dataEpoch(0n), DEK0),
    endpoints: [{ url: "wss://a.example.test", priority: 0n }],
    coordinatorUrl: "wss://a.example.test",
  });
  for (const s of [ALICE, BOB])
    add({ type: "CAPABILITY_GRANT", subject: s.descriptor, abilities: [1n, 2n], delegable: [] });
  const r = validateControlChain(records);
  if (r.kind !== "linear") throw new Error(r.kind);
  return r;
}

/** A device of one Principal: its storage and its section profile. */
class Device {
  readonly view = chain();
  readonly resource = this.view.state.resourceId;
  profile: SharedSectionsDataProfile;
  constructor(
    readonly storage: LfcpStorage,
    readonly who: Signer = ALICE,
  ) {
    this.profile = new SharedSectionsDataProfile(
      SectionReplica.empty({ resource: this.resource, principal: who.descriptor.principalId }),
    );
  }

  /** A restart: the profile from the checkpoint in storage. */
  async restart(): Promise<void> {
    const c = await this.storage.profileState.checkpoint(this.resource);
    if (c === undefined) throw new Error("no checkpoint");
    this.profile = SharedSectionsDataProfile.restore(c, {
      resource: this.resource,
      principal: this.who.descriptor.principalId,
    });
  }

  /** §3.1: stage, adopt, commit with the checkpoint and receipt; undo if the commit does not happen. */
  async commit(intents: SectionIntent[], operationId: string): Promise<Receipt> {
    // §3.3: an operation committed before returns its receipt, before any
    // staging (its intents may no longer apply, e.g. a create that exists).
    const known = await receiptOf(this.storage, this.resource, operationId);
    if (known !== undefined) {
      if (known.intentsHash !== intentsHash(intents)) throw new OperationIdReusedError(operationId);
      return known;
    }
    const replica = this.profile.replica;
    const staged = replica.stage(intents);
    if (staged === null) throw new Error("the batch writes nothing");
    const change = staged.change;
    staged.apply();
    try {
      const { receipt, committed } = await commitOperation(
        this.storage,
        {
          view: this.view,
          controlHead: this.view.state.head,
          actor: this.who,
          dek: DEK0,
          profile: this.profile.codecFor({
            resourceId: this.resource,
            actor: this.who.descriptor.principalId,
          }) as never,
          operationId,
          intents,
          values: [checkChange(change.change)],
          affectedNodeIds: change.affectedNodeIds,
          modelRevision: change.modelRevision,
        },
        (units) => [
          {
            op: "put-profile-checkpoint",
            checkpoint: this.profile.checkpoint(
              units.map((u) => ({ unitId: u.unitId, ref: change.hash })),
            ),
          },
        ],
      );
      if (!committed) {
        // Committed before: this staging is a second copy of the same intents.
        staged.revert();
        return receipt;
      }
      for (const u of receipt.unitIds) this.profile.recordLocal(u, change);
      return receipt;
    } catch (e) {
      staged.revert();
      throw e;
    }
  }
}

const create = (): SectionIntent[] => [
  {
    intent: "section.create",
    sectionId: SECTION,
    title: "S",
    createdBy: ALICE.descriptor.principalId,
  },
  {
    intent: "task.create_in_section",
    task: createTask({ id: T as never, title: "T", createdBy: ALICE.descriptor.principalId }).task,
    parent: SECTION,
    after: null,
  },
];
const para = (): SectionIntent[] => [
  {
    intent: "paragraph.create",
    id: P,
    parent: T,
    after: null,
    text: "p",
    createdBy: ALICE.descriptor.principalId,
  },
];
const nodes = (d: Device) => Object.keys(d.profile.replica.snapshot().nodes).sort();

/** A store whose next commit fails, as a full disk or a killed process would leave it. */
function failingOnce(storage: LfcpStorage): LfcpStorage & { arm(): void } {
  let armed = false;
  return Object.assign(Object.create(storage) as LfcpStorage, {
    arm: () => {
      armed = true;
    },
    commit: (writes: Parameters<LfcpStorage["commit"]>[0]) => {
      if (armed) {
        armed = false;
        return Promise.reject(new Error("disk full"));
      }
      return storage.commit(writes);
    },
  });
}

describe("committing section batches with receipts (§3)", () => {
  it("writes the unit, its outbound entry, the checkpoint and the receipt together", async () => {
    const d = new Device(new InMemoryLfcpStorage());
    const receipt = await d.commit(create(), "op-1");
    expect(receipt.unitIds).toHaveLength(1);
    expect(receipt.affectedNodeIds).toEqual([SECTION, T].sort());
    expect(receipt.modelRevision).toBe(d.profile.replica.revision());
    expect(receipt.durable).toBe(true);
    expect(await receiptOf(d.storage, d.resource, "op-1")).toEqual(receipt);
    const unit = receipt.unitIds[0] as DataUnitId;
    expect((await d.storage.dataUnits.get(unit))?.accepted).toBe(true);
    expect((await d.storage.outbound.list(d.resource)).map((o) => o.kind)).toEqual(["data-unit"]);
    const checkpoint = await d.storage.profileState.checkpoint(d.resource);
    expect(checkpoint?.units.map((u) => toHex(u.unitId))).toEqual([toHex(unit)]);
  });

  it("returns the same receipt for a retry of the same intents, and writes nothing more", async () => {
    const d = new Device(new InMemoryLfcpStorage());
    const first = await d.commit(create(), "op-1");
    const again = await d.commit(create(), "op-1");
    expect(again).toEqual(first);
    expect(d.profile.replica.changes()).toHaveLength(1);
    expect(await d.storage.outbound.list(d.resource)).toHaveLength(1);
  });

  it("refuses the same operation ID for different intents (OPERATION_ID_REUSED)", async () => {
    const d = new Device(new InMemoryLfcpStorage());
    await d.commit(create(), "op-1");
    const before = d.profile.replica.revision();
    await expect(d.commit(para(), "op-1")).rejects.toBeInstanceOf(OperationIdReusedError);
    expect(d.profile.replica.revision()).toBe(before);
    expect(await d.storage.outbound.list(d.resource)).toHaveLength(1);
  });

  it("after a failed commit, nothing exists and a retry commits once", async () => {
    const storage = failingOnce(new InMemoryLfcpStorage());
    const d = new Device(storage);
    await d.commit(create(), "op-1");
    const before = d.profile.replica.revision();
    storage.arm();
    await expect(d.commit(para(), "op-2")).rejects.toThrow("disk full");
    expect(d.profile.replica.revision()).toBe(before);
    expect(await receiptOf(storage, d.resource, "op-2")).toBeUndefined();
    await d.commit(para(), "op-2");
    expect(nodes(d)).toEqual([T, P].sort());
    expect(await storage.outbound.list(d.resource)).toHaveLength(2);
  });

  it("after a crash once the commit happened, a restart finds the receipt and the retry adds nothing", async () => {
    const storage = new InMemoryLfcpStorage();
    const d = new Device(storage);
    await d.commit(create(), "op-1");
    const committed = await d.commit(para(), "op-2");
    // The process dies before the editor learned the outcome; memory is gone.
    const restarted = new Device(storage);
    await restarted.restart();
    expect(await receiptOf(storage, restarted.resource, "op-2")).toEqual(committed);
    expect(await restarted.commit(para(), "op-2")).toEqual(committed);
    expect(nodes(restarted)).toEqual([T, P].sort());
    expect(restarted.profile.replica.changes()).toHaveLength(2);
    // The restored checkpoint knows both units, and the replica writes on.
    await restarted.commit([{ intent: "section.set_title", title: "Next" }], "op-3");
    expect(await storage.outbound.list(restarted.resource)).toHaveLength(3);
  });

  it("releases a receipt", async () => {
    const d = new Device(new InMemoryLfcpStorage());
    await d.commit(create(), "op-1");
    await releaseReceipt(d.storage, d.resource, "op-1");
    expect(await receiptOf(d.storage, d.resource, "op-1")).toBeUndefined();
  });

  it("another client applies the committed units through the Data Unit applier", async () => {
    const d = new Device(new InMemoryLfcpStorage());
    await d.commit(create(), "op-1");
    await d.commit(para(), "op-2");
    const units = await d.storage.outbound.list(d.resource);
    const bob = new SharedSectionsDataProfile(
      SectionReplica.empty({ resource: d.resource, principal: BOB.descriptor.principalId }),
    );
    const handler: DataProfileHandler<CheckedChange> = {
      dataProfile: bob.dataProfile,
      codecFor: (u) => bob.codecFor(u),
      apply: (u, v) => bob.apply(u, v),
      exclude: (ids) => bob.exclude(ids),
    };
    const applier = new DataUnitApplier({
      storage: new InMemoryLfcpStorage(),
      dek: () => DEK0,
      handlers: [handler as DataProfileHandler<unknown>],
    });
    for (const o of units) expect((await applier.receive(d.view, o.bytes)).kind).toBe("applied");
    expect(bob.replica.revision()).toBe(d.profile.replica.revision());
    expect(Object.keys(bob.replica.snapshot().nodes).sort()).toEqual([T, P].sort());
  });
});
