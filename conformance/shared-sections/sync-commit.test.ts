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
  NotWritableError,
  OperationIdReusedError,
  OutboundQueue,
  queueControlRecord,
  receiptOf,
  SyncClient,
  saveControlChain,
  TypingCoalescer,
} from "@openlfcp/client";
import { type ControlRecordId, dataEpoch, resourceId, toHex } from "@openlfcp/core";
import {
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
} from "@openlfcp/crypto";
import { assign, createTask } from "@openlfcp/shared-objects";
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

/** Another principal, for the §6 access cases. */
const party = (seed: number) => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};

interface DeviceOptions {
  /** The client's principal; the owner by default. */
  readonly as?: ReturnType<typeof party>;
  /** Records the owner appends after Genesis, given the IDs so far. */
  readonly records?: (add: (body: ControlBody) => ControlRecordId) => void;
  /** Whether the current epoch's DEK is in the SecretStore (default true). */
  readonly dek?: boolean;
  readonly now?: () => number;
}

async function device(opts: DeviceOptions = {}) {
  const who = opts.as ?? { signer: OWNER, agreement: AGREEMENT };
  const me = who.signer.descriptor.principalId;
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
    return s.recordId;
  };
  add({
    type: "GENESIS",
    dataProfile: SECTIONS_PROFILE_ID,
    owner: OWNER.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
    coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
  });
  opts.records?.(add);
  const view = validateControlChain(records);
  if (view.kind !== "linear") throw new Error(view.kind);
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
  await saveControlChain(storage, view, null);
  if (opts.dek !== false)
    await secrets.put(dekSecretRef(R, dataEpoch(0n)), exportSecretKeyBytes(DEK0));
  const e0 = (await storage.control.epochs(R))[0] as EpochRow;
  await storage.commit([
    { op: "put-epoch", resourceId: R, epoch: { ...e0, dekRef: dekSecretRef(R, dataEpoch(0n)) } },
  ]);

  /** A client of the device's stores with `profile` (a restart builds a new one). */
  const connect = (profile: SharedSectionsDataProfile) => {
    const handler: DataProfileHandler<unknown> = {
      dataProfile: profile.dataProfile,
      codecFor: (u) => profile.codecFor(u) as never,
      apply: (u, v) => profile.apply(u, v as never),
      exclude: (ids) => profile.exclude(ids),
    };
    const sync = new SyncClient({
      url: "ws://127.0.0.1:1/v1/ws",
      signer: who.signer,
      agreement: who.agreement,
      storage,
      secrets,
      outbound: new OutboundQueue({ storage }),
      now: opts.now ?? (() => 0),
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
    return sync;
  };
  const profile = new SharedSectionsDataProfile(
    SectionReplica.empty({ resource: R, principal: me }),
  );
  const sync = connect(profile);
  /** A restart: the profile from its stored checkpoint, a new client on the same stores. */
  const restart = async () => {
    const checkpoint = await storage.profileState.checkpoint(R);
    if (checkpoint === undefined) throw new Error("no checkpoint");
    const restored = SharedSectionsDataProfile.restore(checkpoint as never, {
      resource: R,
      principal: me,
    });
    return { profile: restored, sync: connect(restored) };
  };
  /** Signs the owner's next record on the current head, without storing it. */
  const sign = (body: ControlBody) =>
    signControlRecord(
      { resourceId: R, controlSeq: BigInt(records.length), prevControlId: head },
      body,
      OWNER,
    );
  /** The owner appends a record; the device stores the longer chain. */
  const extend = async (body: ControlBody) => {
    const before = head;
    const id = add(body);
    const next = validateControlChain(records);
    if (next.kind !== "linear") throw new Error(next.kind);
    await saveControlChain(storage, next, before);
    return id;
  };
  return { R, storage, profile, sync, head: view.state.head, sign, extend, restart };
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

describe("SyncClient.canWrite and NOT_WRITABLE (§6, §3.6)", () => {
  const reader = party(30);
  const writer = party(40);
  const grant = (subject: ReturnType<typeof party>, abilities: bigint[]): ControlBody => ({
    type: "CAPABILITY_GRANT",
    subject: subject.signer.descriptor,
    abilities,
    delegable: [],
  });

  it("allows the owner, at the validated head and the time of validation", async () => {
    const d = await device({ now: () => 1_234 });
    expect(await d.sync.canWrite(d.R)).toEqual({
      allowed: true,
      reason: null,
      controlHead: d.head,
      verifiedAt: 1_234,
    });
  });

  it("allows a member granted data/write", async () => {
    const d = await device({ as: writer, records: (add) => add(grant(writer, [1n, 2n])) });
    expect(await d.sync.canWrite(d.R)).toMatchObject({ allowed: true, reason: null });
  });

  it("refuses a read-only member's batch with NOT_WRITABLE and writes nothing", async () => {
    const d = await device({ as: reader, records: (add) => add(grant(reader, [1n])) });
    const access = await d.sync.canWrite(d.R);
    expect(access).toEqual({
      allowed: false,
      reason: "read-only",
      controlHead: d.head,
      verifiedAt: 0,
    });
    const before = d.profile.replica.revision();
    const refused = d.sync.commit(d.R, [create], { operationId: "op-1" });
    await expect(refused).rejects.toBeInstanceOf(NotWritableError);
    await expect(refused).rejects.toMatchObject({ code: "NOT_WRITABLE", access });
    expect(d.profile.replica.revision()).toBe(before);
    expect(await receiptOf(d.storage, d.R, "op-1")).toBeUndefined();
    expect(await d.storage.outbound.list(d.R)).toEqual([]);
  });

  it("tells a revoked member from one never granted", async () => {
    const revoked = await device({
      as: writer,
      records: (add) => add({ type: "CAPABILITY_REVOKE", grantId: add(grant(writer, [1n, 2n])) }),
    });
    expect(await revoked.sync.canWrite(revoked.R)).toMatchObject({
      allowed: false,
      reason: "revoked",
    });
    const stranger = await device({ as: writer });
    expect(await stranger.sync.canWrite(stranger.R)).toMatchObject({
      allowed: false,
      reason: "not-member",
    });
  });

  it("refuses a writer without the current epoch's DEK", async () => {
    const d = await device({ dek: false });
    expect(await d.sync.canWrite(d.R)).toMatchObject({
      allowed: false,
      reason: "key-unavailable",
      controlHead: d.head,
    });
    await expect(d.sync.commit(d.R, [create], { operationId: "op-1" })).rejects.toMatchObject({
      code: "NOT_WRITABLE",
    });
  });

  it("is unknown without a validated chain", async () => {
    const d = await device();
    expect(await d.sync.canWrite(resourceId(bytes32(201)))).toEqual({
      allowed: false,
      reason: "unknown",
      controlHead: null,
      verifiedAt: null,
    });
  });
});

describe("typing coalesced into one unit per burst (LFCP-02-025)", () => {
  it("types 1,000 characters one pass per key into a few units, and the Text is exact", async () => {
    const d = await device();
    const P = id(50);
    await d.sync.commit(
      d.R,
      [
        create,
        {
          intent: "paragraph.create",
          id: P,
          parent: SECTION,
          after: null,
          text: "",
          createdBy: me,
        },
      ],
      { operationId: "setup" },
    );
    // The adapter: each pass is planned against the base of its last receipt.
    const projection = { base: d.profile.replica.revision(), text: "" };
    const advance = () => {
      projection.base = d.profile.replica.revision();
      projection.text = d.profile.replica.snapshot().nodes[P]?.text ?? "";
    };
    const clock = { t: 0 };
    const typing = new TypingCoalescer({
      commit: (intents, o) => d.sync.commit(d.R, intents, o),
      onFlushed: (f) => {
        if (f.kind !== "committed") throw f.error;
        advance();
      },
      now: () => clock.t,
    });
    const typed = "the launch plan needs a review of budget and timeline. "
      .repeat(19)
      .slice(0, 1000);
    let units = 0;
    for (let k = 1; k <= typed.length; k++) {
      clock.t += 120;
      // A pause of 2 s every 300 keys ends a burst.
      if (k % 300 === 0) {
        clock.t += 2_000;
        await typing.tick(clock.t);
      }
      const r = await typing.submit(
        "projection-1",
        [
          {
            intent: "text.edit",
            id: P,
            base: projection.base,
            edits: [
              {
                index: projection.text.length,
                deleteCount: 0,
                insert: typed.slice(projection.text.length, k),
              },
            ],
          },
        ],
        { operationId: `key-${k}` },
      );
      if (r.kind === "committed") {
        units += r.receipt.unitIds.length;
        advance();
      }
    }
    await typing.flush();
    expect(d.profile.replica.snapshot().nodes[P]?.text).toBe(typed);
    // 256 characters a unit while typing on, one more unit per burst end.
    const all = await d.storage.outbound.list(d.R);
    expect(all.length).toBeLessThanOrEqual(10);
    expect(units).toBeGreaterThanOrEqual(3);
  });
});

describe("access with its evidence (LFCP-02-027)", () => {
  const writer = party(40);
  const grant = (abilities: bigint[], claimLimit?: bigint): ControlBody => ({
    type: "CAPABILITY_GRANT",
    subject: writer.signer.descriptor,
    abilities,
    delegable: [],
    ...(claimLimit === undefined ? {} : { claimLimit }),
  });

  it("stays a writer through a remaining grant when another is revoked", async () => {
    let first: ControlRecordId | undefined;
    const d = await device({
      as: writer,
      records: (add) => {
        first = add(grant([1n, 2n]));
        add(grant([1n, 2n]));
      },
    });
    expect((await d.sync.accessState(d.R)).paths).toHaveLength(2);
    await d.extend({ type: "CAPABILITY_REVOKE", grantId: first as ControlRecordId });
    const a = await d.sync.accessState(d.R);
    expect(a).toMatchObject({ allowed: true, reason: null, owner: false, controlSeq: 3n });
    expect(a.abilities).toEqual(["data/read", "data/write"]);
    expect(a.paths).toHaveLength(1);
    expect(a.paths[0]).toMatchObject({ source: "grant", delegated: false });
  });

  it("keeps invitations and pending Control Records apart from access (SI14)", async () => {
    const d = await device({ records: (add) => add(grant([1n, 11n], 1n)) });
    const pending = d.sign({ type: "CAPABILITY_REVOKE", grantId: d.head });
    await queueControlRecord(d.storage, pending.bytes);
    const a = await d.sync.accessState(d.R);
    expect(a.owner).toBe(true);
    expect(a.invitations).toMatchObject([{ claimLimit: 1n, claimsUsed: 0n }]);
    expect(a.pendingControl).toEqual([{ recordId: pending.recordId, type: "CAPABILITY_REVOKE" }]);
    // The removal is requested, not committed: the validated chain is unchanged.
    expect(a.controlSeq).toBe(1n);
    expect(a.pendingClaim).toBe(false);
  });

  it("retains queued work and refuses new work once access is revoked offline (SI15)", async () => {
    let g: ControlRecordId | undefined;
    const d = await device({
      as: writer,
      records: (add) => {
        g = add(grant([1n, 2n]));
      },
    });
    await d.sync.commit(d.R, [{ ...create, createdBy: writer.signer.descriptor.principalId }], {
      operationId: "op-1",
    });
    const queued = await d.storage.outbound.list(d.R);
    expect(queued).toHaveLength(1);
    await d.extend({ type: "CAPABILITY_REVOKE", grantId: g as ControlRecordId });
    expect(await d.sync.accessState(d.R)).toMatchObject({ allowed: false, reason: "revoked" });
    // Enforced here, whatever a server would answer: nothing new is written.
    await expect(
      d.sync.commit(d.R, [{ intent: "section.set_title", title: "T" }], { operationId: "op-2" }),
    ).rejects.toMatchObject({ code: "NOT_WRITABLE" });
    // The queued unit and its receipt stay: no reset as repair.
    expect(await d.storage.outbound.list(d.R)).toEqual(queued);
    expect(await receiptOf(d.storage, d.R, "op-1")).toBeDefined();
  });

  it("grants nothing to an assignee copied into a section Task (CM12)", async () => {
    const d = await device();
    const task = createTask({ id: id(1000) as never, title: "Review", createdBy: me }).task;
    await d.sync.commit(
      d.R,
      [
        create,
        { intent: "task.create_in_section", task, parent: SECTION, after: null },
        assign(task, writer.signer.descriptor.principalId).intent,
      ],
      { operationId: "op-1" },
    );
    expect(d.profile.replica.task(task.id)?.assignees).toHaveLength(1);
    // No Control Record is made or queued: no automatic grant, no fabricated participant.
    const a = await d.sync.accessState(d.R);
    expect(a).toMatchObject({ controlSeq: 0n, pendingControl: [], invitations: [] });
    expect((await d.storage.outbound.list(d.R)).every((item) => item.kind === "data-unit")).toBe(
      true,
    );
    // The assignee, on the same validated chain, is not a member and cannot write.
    const w = await device({ as: writer });
    expect(await w.sync.accessState(w.R)).toMatchObject({
      allowed: false,
      reason: "not-member",
      abilities: [],
      paths: [],
    });
    await expect(w.sync.commit(w.R, [create], { operationId: "op-1" })).rejects.toMatchObject({
      code: "NOT_WRITABLE",
    });
  });

  it("is read-only for a reader with a loaded replica, and freshness is unknown offline (SI18)", async () => {
    const d = await device({ as: writer, records: (add) => add(grant([1n])) });
    expect(await d.sync.accessState(d.R)).toMatchObject({
      allowed: false,
      reason: "read-only",
      abilities: ["data/read"],
      serverControlSeq: null,
      current: null,
    });
  });
});

describe("restart with pending section work (LFCP-02-028)", () => {
  it("keeps the queue and receipts, and continues both sequences", async () => {
    const d = await device();
    await d.sync.commit(d.R, [create, ...tasks(2)], { operationId: "op-1" });
    await d.sync.commit(d.R, tasks(1, 2000), { operationId: "op-2" });
    const queued = await d.storage.outbound.list(d.R);
    const revision = d.profile.replica.revision();
    const actorSeq = d.profile.replica.actorSeq;

    const after = await d.restart();
    // The model is the checkpoint: nothing pending was lost or reset.
    expect(after.profile.replica.revision()).toBe(revision);
    expect(await d.storage.outbound.list(d.R)).toEqual(queued);
    expect((await after.sync.statusSnapshot(d.R)).batches.map((b) => b.status)).toEqual([
      "pending",
      "pending",
    ]);
    // The next commit continues the Automerge actor and the Data Unit sequence.
    const r = await after.sync.commit(d.R, tasks(1, 3000), { operationId: "op-3" });
    expect(after.profile.replica.actorSeq).toBe(actorSeq + 1);
    const units = await Promise.all(
      [...queued.map((q) => q.itemId), ...r.unitIds].map((u) =>
        d.storage.dataUnits.get(u as never),
      ),
    );
    const seqs = units.map((u) => u?.actorSeq);
    expect(seqs).toEqual(
      [...seqs].sort((a, b) => (a === b ? 0 : (a as bigint) < (b as bigint) ? -1 : 1)),
    );
    expect(new Set(seqs.map(String)).size).toBe(seqs.length);
  });
});
