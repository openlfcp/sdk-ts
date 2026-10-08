// LFCP-033: received Data Units applied to the Shared Objects profile, end
// to end through the real packages: @openlfcp/client DataUnitApplier over
// @openlfcp/wire receiveDataUnit (verification order unchanged) and the
// @openlfcp/shared-objects handler over the LFCP-031 Automerge binding.
//
// Synthetic keys and chains. This sits under conformance/ because it needs
// both client and shared-objects, which no package may import together.

import {
  type ApplyOutcome,
  createDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
} from "@openlfcp/client";
import {
  type ActorSequence,
  actorSequence,
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  type ObjectId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  dekCommitment,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  type ResourceDEK,
} from "@openlfcp/crypto";
import {
  addTag,
  type CheckedChange,
  checkChange,
  createTask,
  frameProfilePayload,
  type LocalChange,
  type ObjectChange,
  PROFILE_ID,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
  setStatus,
  setTitle,
  type Task,
} from "@openlfcp/shared-objects";
import { InMemoryLfcpStorage } from "@openlfcp/storage";
import {
  type ChainResult,
  type ControlBody,
  type DataProfileCodec,
  principalDescriptorFromKeys,
  rotateEpoch,
  type Signer,
  sealDataUnit,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";

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
const READER = signer(97);
const DEK0 = importResourceDEK(bytes32(150));
const DEK1 = importResourceDEK(bytes32(151));
const OTHER_DEK = importResourceDEK(bytes32(152));
const TASK_A = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const TASK_B = "017f22e2-79b0-7cc3-98c4-dc0c0c073990" as ObjectId;

type View = Extract<ChainResult, { kind: "linear" }>;

/**
 * A writer's actor sequences (the createDataUnit reservation contract,
 * kept in memory: tests only; @openlfcp/storage is not a root dependency).
 */
class Sequences {
  #last = 0n;
  reserveNext(): Promise<ActorSequence> {
    this.#last += 1n;
    return Promise.resolve(actorSequence(this.#last));
  }
}

/** A Resource's Control Chain: Genesis with `profile`, then grants. */
class Chain {
  readonly resource;
  readonly records: Uint8Array[] = [];
  head: ControlRecordId | null = null;
  constructor(seed: number, profile: string) {
    this.resource = resourceId(bytes32(seed));
    this.add({
      type: "GENESIS",
      dataProfile: profile,
      owner: OWNER.descriptor,
      dekCommitment: dekCommitment(this.resource, dataEpoch(0n), DEK0),
      endpoints: [{ url: "wss://a.example.test", priority: 0n }],
      coordinatorUrl: "wss://a.example.test",
    });
    for (const s of [ALICE, BOB])
      this.add({
        type: "CAPABILITY_GRANT",
        subject: s.descriptor,
        abilities: [1n, 2n],
        delegable: [],
      });
    this.add({
      type: "CAPABILITY_GRANT",
      subject: READER.descriptor,
      abilities: [1n],
      delegable: [],
    });
  }
  add(body: ControlBody): void {
    const s = signControlRecord(
      {
        resourceId: this.resource,
        controlSeq: BigInt(this.records.length),
        prevControlId: this.head,
      },
      body,
      OWNER,
    );
    this.records.push(s.bytes);
    this.head = s.recordId;
  }
  view(extra: readonly Uint8Array[] = []): View {
    const r = validateControlChain([...this.records, ...extra]);
    if (r.kind !== "linear") throw new Error(r.kind);
    return r;
  }
}

/** A writing client: its replica, its profile codec and its LFCP actor chain. */
class Writer {
  readonly replica: SharedObjectsReplica;
  readonly profile: SharedObjectsDataProfile;
  readonly sequences = new Sequences();
  previous: DataUnitId | null = null;
  constructor(
    readonly chain: Chain,
    readonly who: Signer,
    replica?: SharedObjectsReplica,
  ) {
    this.replica = replica ?? SharedObjectsReplica.empty(this.options());
    this.profile = new SharedObjectsDataProfile(this.replica);
  }
  options() {
    return { resource: this.chain.resource, principal: this.who.descriptor.principalId };
  }
  /** Seals one change as this writer's next Data Unit. */
  async send(
    change: CheckedChange | LocalChange,
    o: { view?: View; dek?: ResourceDEK; codec?: DataProfileCodec<CheckedChange> } = {},
  ): Promise<{ bytes: Uint8Array; unitId: DataUnitId }> {
    const view = o.view ?? this.chain.view();
    const value = "plaintext" in change ? checkChange(change.change) : change;
    const u = await createDataUnit({
      view,
      controlHead: view.state.head,
      actor: this.who,
      dek: o.dek ?? DEK0,
      sequences: this.sequences,
      previousUnitId: this.previous,
      profile:
        o.codec ??
        this.profile.codecFor({
          resourceId: this.chain.resource,
          actor: this.who.descriptor.principalId,
        }),
      value,
    });
    this.previous = u.unitId;
    return u;
  }
}

/** A receiving client with its applier; apply calls and DEK requests are counted. */
function receiver(chain: Chain, who: Signer = READER) {
  const replica = SharedObjectsReplica.empty({
    resource: chain.resource,
    principal: who.descriptor.principalId,
  });
  const profile = new SharedObjectsDataProfile(replica);
  const counts = { apply: 0, dek: 0 };
  const handler: DataProfileHandler<CheckedChange> = {
    dataProfile: profile.dataProfile,
    codecFor: (u) => profile.codecFor(u),
    apply: (u, v) => {
      counts.apply++;
      return profile.apply(u, v);
    },
    exclude: (ids) => profile.exclude(ids),
  };
  const deks = new Map([
    ["0", DEK0],
    ["1", DEK1],
  ]);
  const storage = new InMemoryLfcpStorage();
  const applier = new DataUnitApplier({
    storage,
    dek: (epoch) => {
      counts.dek++;
      return deks.get(String(epoch));
    },
    handlers: [handler as DataProfileHandler<unknown>],
  });
  return { applier, profile, counts, storage };
}

/** Alice's Resource: the owner initializes it, Alice creates a Task; their two units. */
async function resource() {
  const chain = new Chain(200, PROFILE_ID);
  const { replica: ownerReplica, change: init } = SharedObjectsReplica.create({
    resource: chain.resource,
    principal: OWNER.descriptor.principalId,
  });
  const owner = new Writer(chain, OWNER, ownerReplica);
  const initUnit = await owner.send(init);
  const alice = new Writer(
    chain,
    ALICE,
    SharedObjectsReplica.fromChanges(owner.replica.changes(), {
      resource: chain.resource,
      principal: ALICE.descriptor.principalId,
    }).replica,
  );
  const created = alice.replica.apply(
    createTask({
      id: TASK_A,
      title: "Prepare API contract",
      createdBy: ALICE.descriptor.principalId,
    }).intent,
  ) as LocalChange;
  const createUnit = await alice.send(created);
  return { chain, owner, alice, initUnit, createUnit };
}

const taskOf = (r: SharedObjectsReplica, id: ObjectId = TASK_A): Task => {
  const t = r.task(id)?.task;
  if (t === undefined) throw new Error(`no valid Task ${id}`);
  return t;
};

const kinds = (outcomes: readonly ApplyOutcome[]) => outcomes.map((o) => o.kind);

describe("LFCP-033: applying Data Units to the Shared Objects profile", () => {
  it("1, 15. applies valid units into the expected semantic state", async () => {
    const { chain, initUnit, createUnit } = await resource();
    const { applier, profile } = receiver(chain);
    const view = chain.view();
    expect(await applier.receive(view, initUnit.bytes)).toMatchObject({
      kind: "applied",
      dataProfile: PROFILE_ID,
      haveEligible: false,
    });
    const created = await applier.receive(view, createUnit.bytes);
    expect(created).toMatchObject({ kind: "applied", objects: [TASK_A], diagnostics: [] });
    expect(taskOf(profile.replica)).toMatchObject({
      title: "Prepare API contract",
      status: "todo",
    });
    expect(profile.replica.task(TASK_A)?.status).toBe("ready");
  });

  it("2, 3. an exact replay is harmless and creates nothing to send", async () => {
    const { chain, initUnit, createUnit } = await resource();
    const { applier, profile, counts } = receiver(chain);
    const view = chain.view();
    for (const u of [initUnit, createUnit]) await applier.receive(view, u.bytes);
    const before = {
      root: profile.replica.root(),
      heads: profile.replica.heads(),
      applies: counts.apply,
    };
    expect(await applier.receive(view, createUnit.bytes)).toMatchObject({ kind: "duplicate" });
    expect(await applier.receive(view, initUnit.bytes)).toMatchObject({ kind: "duplicate" });
    expect(profile.replica.root()).toEqual(before.root);
    expect(profile.replica.heads()).toEqual(before.heads);
    expect(counts.apply).toBe(before.applies);
    // No local change: the receiver's own actor wrote nothing.
    expect(profile.replica.actorSeq).toBe(0);
  });

  it("4, G-DP5. a second unit for one (resource, actor, seq) is equivocation: neither stays merged", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const { applier, profile, counts, storage } = receiver(chain);
    const view = chain.view();
    for (const u of [initUnit, createUnit]) await applier.receive(view, u.bytes);
    // Alice's lost-state twin reuses her sequence 1 with other content.
    const twin = new Writer(
      chain,
      ALICE,
      SharedObjectsReplica.fromChanges(alice.replica.changes().slice(0, 1), alice.options())
        .replica,
    );
    const other = twin.replica.apply(
      createTask({ id: TASK_B, title: "Other", createdBy: ALICE.descriptor.principalId }).intent,
    ) as LocalChange;
    const forged = await twin.send(other);
    const applies = counts.apply;
    const r = await applier.receive(view, forged.bytes);
    expect(r).toMatchObject({ kind: "equivocation", wireCode: "ACTOR_EQUIVOCATION" });
    if (r.kind === "equivocation") {
      expect(r.unitIds.map(toHex).sort()).toEqual(
        [createUnit.unitId, forged.unitId].map(toHex).sort(),
      );
      expect(toHex(r.accepted as DataUnitId)).toBe(toHex(createUnit.unitId));
    }
    expect(counts.apply).toBe(applies);
    // LFCP-WIRE-01 §26.2 (G-DP5): the merged unit is taken out too, so no arrival order wins.
    expect(r.kind === "equivocation" && r.excluded.map(toHex)).toEqual([toHex(createUnit.unitId)]);
    expect(r.kind === "equivocation" && r.objects).toEqual([TASK_A]);
    expect(profile.replica.objectIds()).toEqual([]);
    for (const u of [createUnit, forged]) {
      expect(await storage.dataUnits.get(u.unitId)).toMatchObject({
        status: "equivocation",
        accepted: false,
        bytes: u.bytes,
      });
    }
    // A replay of either stays equivocation, never a duplicate or a merge.
    expect((await applier.receive(view, createUnit.bytes)).kind).toBe("equivocation");
    expect(profile.replica.objectIds()).toEqual([]);
  });

  it("POST-001. a change whose actor sequence is taken is held, kept and released by the rebuild", async () => {
    const { chain, initUnit, createUnit, owner, alice } = await resource();
    const { applier, profile, storage } = receiver(chain);
    const view = chain.view();
    // Bob builds c on Alice's X (her sequence 1).
    const bob = new Writer(
      chain,
      BOB,
      SharedObjectsReplica.fromChanges(alice.replica.changes(), {
        resource: chain.resource,
        principal: BOB.descriptor.principalId,
      }).replica,
    );
    const c = await bob.send(
      bob.replica.apply(setTitle(taskOf(bob.replica), "Bob's title").intent) as LocalChange,
    );
    // Bob learned that X is one of an equivocating pair, rebuilt without it
    // and re-issued his work: Automerge sequence 1 again, LFCP sequence 2.
    const rebuilt = SharedObjectsReplica.fromChanges(owner.replica.changes(), {
      resource: chain.resource,
      principal: BOB.descriptor.principalId,
    }).replica;
    const c2 = await bob.send(
      rebuilt.apply(
        createTask({ id: TASK_B, title: "Re-issued", createdBy: BOB.descriptor.principalId })
          .intent,
      ) as LocalChange,
    );
    for (const u of [initUnit, createUnit, c])
      expect((await applier.receive(view, u.bytes)).kind).toBe("applied");
    // The receiver does not know of the equivocation yet: c2 is held, not refused.
    const held = await applier.receive(view, c2.bytes);
    expect(held).toMatchObject({ kind: "profile-held", seq: 2n });
    expect(await storage.dataUnits.get(c2.unitId)).toMatchObject({
      status: "profile-held",
      accepted: true,
    });
    expect(profile.replica.task(TASK_B)).toBeUndefined();
    // Alice's other unit at her sequence 1 arrives: the rebuild without X
    // drops c (it builds on X) and frees Bob's sequence 1 for c2.
    const twin = new Writer(
      chain,
      ALICE,
      SharedObjectsReplica.fromChanges(owner.replica.changes(), alice.options()).replica,
    );
    const forged = await twin.send(
      twin.replica.apply(
        createTask({ id: TASK_A, title: "Other", createdBy: ALICE.descriptor.principalId }).intent,
      ) as LocalChange,
    );
    const r = await applier.receive(view, forged.bytes);
    expect(r.kind).toBe("equivocation");
    if (r.kind !== "equivocation") return;
    expect(r.pending.map(toHex)).toEqual([toHex(c.unitId)]);
    expect(r.released.map((x) => [x.kind, "unitId" in x ? toHex(x.unitId) : ""])).toEqual([
      ["applied", toHex(c2.unitId)],
    ]);
    expect(await storage.dataUnits.get(c2.unitId)).toMatchObject({ status: "merged" });
    expect(taskOf(profile.replica, TASK_B).title).toBe("Re-issued");
  });

  it("5, 6, 8. invalid signature, missing data/write and AEAD failure never reach the profile", async () => {
    const { chain, initUnit, alice } = await resource();
    const { applier, counts } = receiver(chain);
    const view = chain.view();
    await applier.receive(view, initUnit.bytes);
    const applies = counts.apply;

    const change = checkChange(alice.replica.changes()[1] as Uint8Array);
    const good = await alice.send(change);
    const badSignature = Uint8Array.from(good.bytes);
    badSignature[badSignature.length - 1] = (badSignature[badSignature.length - 1] as number) ^ 1;
    expect(await applier.receive(view, badSignature)).toMatchObject({
      kind: "rejected",
      wireCode: "INVALID_SIGNATURE",
    });

    // Framed directly: these units must fail before any profile check.
    const plaintext = frameProfilePayload(change.bytes);
    const header = {
      resourceId: chain.resource,
      dataEpoch: dataEpoch(0n),
      actorSeq: actorSequence(1n),
      prevDataUnitId: null,
      controlHead: view.state.head as ControlRecordId,
    };
    const unauthorized = sealDataUnit(header, plaintext, DEK0, READER);
    expect(await applier.receive(view, unauthorized.bytes)).toMatchObject({
      kind: "rejected",
      wireCode: "AUTHORIZATION_FAILED",
    });

    const wrongKey = sealDataUnit(header, plaintext, OTHER_DEK, BOB);
    expect(await applier.receive(view, wrongKey.bytes)).toMatchObject({
      kind: "local-failure",
      reason: "AEAD",
    });
    expect(counts.apply).toBe(applies);
  });

  it("7. a unit beyond a closed epoch's cutoff is quarantined, never applied", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const rotation = rotateEpoch(chain.view().state, OWNER, {
      reason: 0n,
      finalFrontier: [
        { principalId: OWNER.descriptor.principalId, contiguous: 1n, extras: [] },
        { principalId: ALICE.descriptor.principalId, contiguous: 1n, extras: [] },
      ],
      dek: DEK1,
    });
    const late = alice.replica.apply(
      setStatus(taskOf(alice.replica), "in_progress").intent,
    ) as LocalChange;
    const lateUnit = await alice.send(late); // epoch 0, sequence 2: beyond the frontier
    const { applier, counts, storage } = receiver(chain);
    const rotated = chain.view([rotation.bytes]);
    for (const u of [initUnit, createUnit]) await applier.receive(rotated, u.bytes);
    const applies = counts.apply;
    const r = await applier.receive(rotated, lateUnit.bytes);
    expect(r).toMatchObject({
      kind: "quarantined",
      code: "STALE_DATA_EPOCH",
      reason: "BEYOND_CUTOFF",
    });
    expect(counts.apply).toBe(applies);
    expect((await storage.dataUnits.get(lateUnit.unitId))?.status).toBe("quarantined");
  });

  it("9. a Resource of an unknown Data Profile is PROFILE_UNSUPPORTED, never decrypted", async () => {
    const chain = new Chain(210, "org.example.unknown.v1");
    const owner = new Writer(chain, OWNER);
    const opaque: DataProfileCodec<CheckedChange> = {
      dataProfile: "org.example.unknown.v1",
      encode: () => Uint8Array.of(1, 2, 3),
      decode: () => {
        throw new Error("never");
      },
    };
    const u = await owner.send(
      checkChange(SharedObjectsReplica.create(owner.options()).change.change),
      { codec: opaque },
    );
    const { applier, counts, storage } = receiver(chain);
    expect(await applier.receive(chain.view(), u.bytes)).toMatchObject({
      kind: "profile-unsupported",
      code: "PROFILE_UNSUPPORTED",
      dataProfile: "org.example.unknown.v1",
    });
    expect(counts).toEqual({ apply: 0, dek: 0 });
    expect((await storage.dataUnits.get(u.unitId))?.bytes).toEqual(u.bytes);
  });

  it("10, 11, 14. bad framing or Automerge bytes are rejected, not merged, and the exact unit is kept", async () => {
    const { chain, initUnit, alice } = await resource();
    const { applier, profile, counts, storage } = receiver(chain);
    const view = chain.view();
    await applier.receive(view, initUnit.bytes);
    const raw = (plaintext: Uint8Array): DataProfileCodec<CheckedChange> => ({
      dataProfile: PROFILE_ID,
      encode: () => plaintext,
      decode: () => {
        throw new Error("sender side only");
      },
    });
    const change = checkChange(alice.replica.changes()[1] as Uint8Array);
    const noFraming = await alice.send(change, { codec: raw(change.bytes) });
    const notAutomerge = await alice.send(change, {
      codec: raw(frameProfilePayload(Uint8Array.of(1, 2, 3))),
    });
    for (const u of [noFraming, notAutomerge]) {
      expect(await applier.receive(view, u.bytes)).toMatchObject({
        kind: "local-failure",
        reason: "PROFILE_REJECTED",
      });
      const kept = await storage.dataUnits.get(u.unitId);
      expect([kept?.status, kept?.bytes]).toEqual(["local-failure", u.bytes]);
    }
    expect(counts.apply).toBe(1);
    expect(profile.replica.objectIds()).toEqual([]);
  });

  it("SO-SEC1: a unit carrying another Principal's Automerge actor is rejected", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const { applier, profile } = receiver(chain);
    const view = chain.view();
    await applier.receive(view, initUnit.bytes);
    // Bob signs a unit whose change was written by Alice's §8 actor.
    const bob = new Writer(chain, BOB);
    const aliceCodec = alice.profile.codecFor({
      resourceId: chain.resource,
      actor: ALICE.descriptor.principalId,
    });
    const stolen = await bob.send(checkChange(alice.replica.changes()[1] as Uint8Array), {
      codec: aliceCodec,
    });
    const r = await applier.receive(view, stolen.bytes);
    expect(r).toMatchObject({ kind: "local-failure", reason: "PROFILE_REJECTED" });
    expect(r.kind === "local-failure" && r.message).toMatch(/SO-SEC1/);
    // §11, §74.1: PROFILE_INVALID with the diagnostic CHANGE_ACTOR_MISMATCH.
    expect(r.kind === "local-failure" && r.error).toMatchObject({
      code: "PROFILE_INVALID",
      diagnostic: "CHANGE_ACTOR_MISMATCH",
    });
    expect(profile.replica.objectIds()).toEqual([]);
    // The same change in Alice's own unit merges.
    expect(await applier.receive(view, createUnit.bytes)).toMatchObject({ kind: "applied" });
  });

  it("holds a unit whose actor chain has a gap and merges it when the gap closes (G-DP1)", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const second = await alice.send(
      alice.replica.apply(setTitle(taskOf(alice.replica), "Final").intent) as LocalChange,
    );
    const { applier, profile } = receiver(chain);
    const view = chain.view();
    await applier.receive(view, initUnit.bytes);
    expect(await applier.receive(view, second.bytes)).toMatchObject({
      kind: "held",
      reason: "GAP",
    });
    expect(profile.replica.objectIds()).toEqual([]);
    const first = await applier.receive(view, createUnit.bytes);
    expect(first.kind === "applied" && kinds(first.released)).toEqual(["applied"]);
    expect(taskOf(profile.replica).title).toBe("Final");
  });

  it("buffers a unit whose Automerge dependencies are missing (profile-pending), distinct from held", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const bob = new Writer(
      chain,
      BOB,
      SharedObjectsReplica.fromChanges(alice.replica.changes(), {
        resource: chain.resource,
        principal: BOB.descriptor.principalId,
      }).replica,
    );
    const tagged = await bob.send(
      bob.replica.apply(addTag(taskOf(bob.replica), "backend").intent) as LocalChange,
    );
    const { applier, profile, storage } = receiver(chain);
    const view = chain.view();
    await applier.receive(view, initUnit.bytes);
    const early = await applier.receive(view, tagged.bytes);
    expect(early).toMatchObject({ kind: "profile-pending", haveEligible: false });
    expect((await storage.dataUnits.get(tagged.unitId))?.status).toBe("profile-pending");
    const r = await applier.receive(view, createUnit.bytes);
    expect(r.kind === "applied" && r.alsoMerged.map(toHex)).toEqual([toHex(tagged.unitId)]);
    expect((await storage.dataUnits.get(tagged.unitId))?.status).toBe("merged");
    expect(profile.replica.task(TASK_A)?.tags).toEqual(["backend"]);
    expect(profile.pendingUnits()).toEqual([]);
  });

  it("12, 13. an Object ID collision is isolated to its object; the others stay usable (§21, §77)", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const bob = new Writer(
      chain,
      BOB,
      SharedObjectsReplica.fromChanges(alice.replica.changes(), {
        resource: chain.resource,
        principal: BOB.descriptor.principalId,
      }).replica,
    );
    const owner2 = SharedObjectsReplica.fromChanges(alice.replica.changes().slice(0, 1), {
      resource: chain.resource,
      principal: OWNER.descriptor.principalId,
    }).replica;
    // Bob creates TASK_B; concurrently the owner creates another object under the same ID.
    const bobUnit = await bob.send(
      bob.replica.apply(
        createTask({ id: TASK_B, title: "Bob's", createdBy: BOB.descriptor.principalId }).intent,
      ) as LocalChange,
    );
    const ownerWriter = new Writer(chain, OWNER, owner2);
    ownerWriter.previous = initUnit.unitId;
    await ownerWriter.sequences.reserveNext(); // sequence 1 is the init unit
    const ownerUnit = await ownerWriter.send(
      owner2.apply(
        createTask({ id: TASK_B, title: "Owner's", createdBy: OWNER.descriptor.principalId })
          .intent,
      ) as LocalChange,
    );
    const { applier, profile } = receiver(chain);
    const view = chain.view();
    for (const u of [initUnit, createUnit, bobUnit]) await applier.receive(view, u.bytes);
    const r = await applier.receive(view, ownerUnit.bytes);
    expect(r).toMatchObject({
      kind: "applied",
      diagnostics: [expect.objectContaining({ objectId: TASK_B, code: "OBJECT_ID_COLLISION" })],
    });
    expect(profile.replica.task(TASK_B)?.status).toBe("object_id_collision");
    expect(profile.replica.task(TASK_A)?.status).toBe("ready");
    // The unrelated Task stays writable.
    expect(profile.replica.apply(setStatus(taskOf(profile.replica), "done").intent)).not.toBeNull();
  });

  // LFCP-WIRE-01 §19.1, SHARED-OBJECTS-PROFILE-01 §14.1 (G-EP7)
  it("rebuilds without a merged unit that a new Key Epoch puts beyond its cutoff, and notifies", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const d = await alice.send(
      alice.replica.apply(setStatus(taskOf(alice.replica), "done").intent) as LocalChange,
    );
    const { applier, profile, storage } = receiver(chain);
    const view = chain.view();
    for (const u of [initUnit, createUnit, d])
      expect(await applier.receive(view, u.bytes)).toMatchObject({ kind: "applied" });
    expect(taskOf(profile.replica).status).toBe("done");
    const notified: ObjectChange[] = [];
    profile.onObjectChanged((c) => notified.push(c));

    // The epoch closes with Alice's frontier at sequence 1: D (sequence 2) is beyond the cutoff.
    const rotation = rotateEpoch(view.state, OWNER, {
      reason: 0n,
      finalFrontier: [
        { principalId: OWNER.descriptor.principalId, contiguous: 1n, extras: [] },
        { principalId: ALICE.descriptor.principalId, contiguous: 1n, extras: [] },
      ],
      dek: DEK1,
    });
    const r = await applier.reconcileEpochs(chain.view([rotation.bytes]));
    expect(r.excluded.map((e) => toHex(e.unitId))).toEqual([toHex(d.unitId)]);
    expect(r.excluded[0]?.quarantine).toMatchObject({
      code: "STALE_DATA_EPOCH",
      reason: "BEYOND_CUTOFF",
    });
    expect(r.objects).toEqual([TASK_A]);
    expect(taskOf(profile.replica).status).toBe("todo");
    expect(notified).toEqual([
      expect.objectContaining({ objectId: TASK_A, fields: ["status"], origin: "rebuild" }),
    ]);
    expect((await storage.dataUnits.get(d.unitId))?.status).toBe("quarantined");
    // Idempotent: nothing more to exclude.
    expect((await applier.reconcileEpochs(chain.view([rotation.bytes]))).excluded).toEqual([]);
  });

  it("applies each unit once whatever the delivery order (seeded property test)", async () => {
    const { chain, initUnit, createUnit, alice } = await resource();
    const bob = new Writer(
      chain,
      BOB,
      SharedObjectsReplica.fromChanges(alice.replica.changes(), {
        resource: chain.resource,
        principal: BOB.descriptor.principalId,
      }).replica,
    );
    const units = [initUnit, createUnit];
    for (const [i, title] of ["one", "two", "three"].entries()) {
      units.push(
        await alice.send(
          alice.replica.apply(setTitle(taskOf(alice.replica), title).intent) as LocalChange,
        ),
      );
      units.push(
        await bob.send(
          bob.replica.apply(addTag(taskOf(bob.replica), `tag-${i}`).intent) as LocalChange,
        ),
      );
    }
    // The reference: every change, merged directly.
    const reference = SharedObjectsReplica.fromChanges(
      [...alice.replica.changes(), ...bob.replica.changes()],
      { resource: chain.resource, principal: READER.descriptor.principalId },
    ).replica;
    const view = chain.view();
    let seed = 0x5eed;
    const random = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x80000000;
    };
    for (let run = 0; run < 25; run++) {
      const { applier, profile, counts, storage } = receiver(chain);
      // Every unit at least once, with replays, in a random order.
      const deliveries = [...units, ...units.filter(() => random() < 0.5)];
      for (let i = deliveries.length - 1; i > 0; i--) {
        const j = Math.floor(random() * (i + 1));
        [deliveries[i], deliveries[j]] = [
          deliveries[j] as (typeof units)[number],
          deliveries[i] as (typeof units)[number],
        ];
      }
      for (const u of deliveries) await applier.receive(view, u.bytes);
      expect(counts.apply).toBe(units.length);
      expect((await storage.dataUnits.withStatus(chain.resource, "merged")).length).toBe(
        units.length,
      );
      expect(profile.replica.root()).toEqual(reference.root());
      for (const u of units)
        expect(await applier.receive(view, u.bytes)).toMatchObject({ kind: "duplicate" });
      expect(profile.replica.root()).toEqual(reference.root());
    }
  });
});
