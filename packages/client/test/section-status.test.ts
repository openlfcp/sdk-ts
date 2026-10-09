import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  hash32,
  resourceId,
  toHex,
} from "@openlfcp/core";
import {
  type AgreementKeyPair,
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importResourceDEK,
  importSigningKey,
  sha256 as sha,
} from "@openlfcp/crypto";
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  InMemorySecretStore,
} from "@openlfcp/storage";
import {
  type AnyMessage,
  type ControlBody,
  type DataProfileCodec,
  ERROR_CODE,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  batchStatus,
  type CommitBinding,
  createQueuedDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
  dekResolver,
  OutboundQueue,
  queueControlRecord,
  releaseReceipt,
  type StatusEvent,
  SyncClient,
  saveControlChain,
} from "../src/index.js";
import { FakeServer, settle } from "./fake-server.js";

// LFCP-02-026, SDK-SECTIONS-INTEGRATION-01 §4–§5: the status of committed
// batches from the server's correlated durable ACKs, rejection, re-offer
// after a loss, received units, section state and access, as one stream
// with a revision per Resource, and statusSnapshot.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const party = (seed: number): { signer: Signer; agreement: AgreementKeyPair } => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const OWNER = party(1);
const PROFILE = "org.example.text.v1";
const DEK0 = importResourceDEK(bytes32(90));
const URL = "ws://127.0.0.1:1/v1/ws";
const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (p) => String.fromCharCode(...p),
};

/** A Resource of OWNER whose route is `url`. */
function chainFor(seed: number, url = URL) {
  const R = resourceId(bytes32(seed));
  const records: Uint8Array[] = [];
  const ids: ControlRecordId[] = [];
  const add = (body: ControlBody) => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: BigInt(records.length), prevControlId: ids.at(-1) ?? null },
      body,
      OWNER.signer,
    );
    records.push(s.bytes);
    ids.push(s.recordId);
  };
  add({
    type: "GENESIS",
    dataProfile: PROFILE,
    owner: OWNER.signer.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url, priority: 0n }],
    coordinatorUrl: url,
  });
  const view = () => {
    const r = validateControlChain(records);
    if (r.kind !== "linear") throw new Error(r.kind);
    return r;
  };
  return { R, records, ids, view, add };
}

/**
 * A server holding `chain` and the units put to it. `put` decides each
 * DATA_PUT's answer: "ack" (durable), "plain" (not durable), "silent" or a
 * NACK code; it stores the units it acknowledges.
 */
function serve(server: FakeServer, chain: ReturnType<typeof chainFor>) {
  const state = {
    stored: [] as Uint8Array[],
    put: "ack" as "ack" | "plain" | "silent" | bigint,
  };
  server.onMessage = (m: AnyMessage, s) => {
    const reply = (type: AnyMessage["type"], body: unknown) =>
      s.reply(m, type as never, body as never);
    const v = chain.view();
    const haves =
      state.stored.length === 0
        ? []
        : [
            {
              principalId: OWNER.signer.descriptor.principalId,
              contiguous: BigInt(state.stored.length),
            },
          ];
    switch (m.type) {
      case "RESOURCE_OPEN":
        reply("RESOURCE_OPENED", {
          resourceId: chain.R,
          heads: [{ seq: v.state.seq, recordId: v.state.head }],
          haves,
        });
        break;
      case "CONTROL_GET":
        reply("CONTROL_BATCH", {
          resourceId: chain.R,
          objects: chain.records.slice(Number(m.body.start), Number(m.body.end) + 1),
        });
        break;
      case "KEY_PACKAGE_GET":
        reply("KEY_PACKAGE_BATCH", { resourceId: chain.R, objects: [] });
        break;
      case "DATA_HAVE":
        reply("DATA_HAVE", { resourceId: chain.R, haves });
        break;
      case "DATA_GET":
        reply("DATA_BATCH", { resourceId: chain.R, objects: state.stored });
        break;
      case "DATA_PUT": {
        const put = state.put;
        if (put === "silent") break;
        if (typeof put === "bigint") {
          reply("NACK", { code: put });
          break;
        }
        for (const o of m.body.objects)
          if (!state.stored.some((x) => toHex(x) === toHex(o))) state.stored.push(o);
        reply("ACK", {
          requestType: 33n,
          objectIds: m.body.objects.map((o) => hash32(sha(o))),
          ...(put === "ack" ? { durable: true } : {}),
        });
        break;
      }
    }
    return [];
  };
  return state;
}

/** OWNER's device with a commit binding over the text profile. */
async function device(
  server: FakeServer,
  chain: ReturnType<typeof chainFor>,
  /** How many of the chain's records the device knows (default all). */
  known = chain.records.length,
  /** The Snapshot policy; with it the Resource gets a Snapshot binding. */
  snapshotPolicy?: (resource: unknown, units: number) => boolean,
) {
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
  const view = validateControlChain(chain.records.slice(0, known));
  if (view.kind !== "linear") throw new Error(view.kind);
  await saveControlChain(storage, view, null);
  await secrets.put(dekSecretRef(chain.R, dataEpoch(0n)), exportSecretKeyBytes(DEK0));
  const e0 = (await storage.control.epochs(chain.R))[0] as EpochRow;
  await storage.commit([
    {
      op: "put-epoch",
      resourceId: chain.R,
      epoch: { ...e0, dekRef: dekSecretRef(chain.R, dataEpoch(0n)) },
    },
  ]);
  const handler: DataProfileHandler<string> = {
    dataProfile: PROFILE,
    codecFor: () => TEXT,
    // "w" waits for a dependency, "h" is held, "x" is refused; anything else merges.
    apply: (u, v) => {
      if (v === "x") throw new Error("refused: x is not a valid change");
      return v === "w"
        ? { merged: [], objects: [], diagnostics: [], pending: "waits for its dependency" }
        : v === "h"
          ? { merged: [], objects: [], diagnostics: [], held: "held" }
          : { merged: [u.unitId], objects: [], diagnostics: [] };
    },
    exclude: () => ({ objects: [], pending: [] }),
  };
  const model = { section: undefined as "ready" | "importing" | undefined, revision: 0 };
  const clock = { t: 0 };
  const commit: CommitBinding<string> = {
    codec: TEXT,
    section: () => model.section,
    stage: (intents) => ({
      values: intents as string[],
      affectedNodeIds: ["n1"],
      modelRevision: `r${model.revision + 1}`,
      apply: () => {
        model.revision += 1;
      },
      revert: () => {
        model.revision -= 1;
      },
      writes: () => [],
      committed: () => {},
    }),
  };
  const sync = new SyncClient({
    url: URL,
    signer: OWNER.signer,
    agreement: OWNER.agreement,
    storage,
    secrets,
    outbound: new OutboundQueue({ storage }),
    now: () => clock.t,
    webSocket: server.factory,
    reconnect: () => 1000,
    ...(snapshotPolicy === undefined ? {} : { snapshotPolicy }),
  });
  const events: StatusEvent[] = [];
  sync.on((e) => {
    if (e.type === "status") events.push(e.event);
  });
  sync.open({
    resourceId: chain.R,
    applier: new DataUnitApplier({
      storage,
      dek: dekResolver(storage, secrets, chain.R),
      handlers: [handler as DataProfileHandler<unknown>],
    }),
    commit: commit as CommitBinding<unknown>,
    ...(snapshotPolicy === undefined
      ? {}
      : { snapshot: { codec: TEXT, load: () => {}, current: () => "state" } as never }),
  });
  const live = async () => {
    sync.start();
    await settle(200);
    await sync.idle();
    expect(sync.resourceState(chain.R)).toBe("LIVE");
  };
  /** Moves the clock and runs the session's timers. */
  const at = async (t: number) => {
    clock.t = t;
    await d.sync.tick(t);
    await settle(100);
    await d.sync.idle();
  };
  const d = { storage, sync, events, model, live, at };
  return d;
}

/** The events' kinds (batches with their status), catch-up aside. */
const kinds = (events: readonly StatusEvent[]) =>
  events
    .filter((e) => e.kind !== "catch-up")
    .map((e) => (e.kind === "batch" ? `batch:${e.status}` : e.kind));

describe("batch status from server evidence (§4.1)", () => {
  it("is pending until a correlated durable ACK accepts every unit", async () => {
    const server = new FakeServer();
    const chain = chainFor(220);
    const srv = serve(server, chain);
    const d = await device(server, chain);
    srv.put = "silent";
    await d.live();
    const receipt = await d.sync.commit(chain.R, ["a", "b"], { operationId: "op-1" });
    await settle(50);
    expect(receipt.unitIds).toHaveLength(2);
    expect(await batchStatus(d.storage, chain.R, "op-1", 2n)).toMatchObject({
      status: "pending",
      acceptedUnitIds: [],
    });
    // The ACK is lost: sent again later, acknowledged as a duplicate (§70).
    srv.put = "ack";
    await d.at(60_000);
    const b = await batchStatus(d.storage, chain.R, "op-1", 2n);
    expect(b?.status).toBe("accepted");
    expect(b?.acceptedUnitIds.map(toHex)).toEqual(receipt.unitIds.map(toHex));
    expect(kinds(d.events)).toEqual(["access", "batch:pending", "batch:accepted"]);
    // Revisions count every event of the Resource from 1.
    expect(d.events.map((e) => e.revision)).toEqual(d.events.map((_, i) => i + 1));
    // Released, the batch and its status are gone.
    await releaseReceipt(d.storage, chain.R, "op-1");
    expect(await batchStatus(d.storage, chain.R, "op-1", 2n)).toBeUndefined();
    expect((await d.storage.localMarks.list("batch-status:")).length).toBe(0);
    expect((await d.storage.localMarks.list("receipt-unit:")).length).toBe(0);
  });

  it("is evidence-unavailable on a server below durability 2, and for an ACK not durable", async () => {
    const server = new FakeServer();
    server.durability = 1n;
    const chain = chainFor(221);
    serve(server, chain);
    const d = await device(server, chain);
    await d.live();
    await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d.sync.idle();
    expect((await d.sync.statusSnapshot(chain.R)).batches).toMatchObject([
      { operationId: "op-1", status: "evidence-unavailable", acceptedUnitIds: [] },
    ]);

    const s2 = new FakeServer();
    const chain2 = chainFor(222);
    const srv2 = serve(s2, chain2);
    srv2.put = "plain";
    const d2 = await device(s2, chain2);
    await d2.live();
    await d2.sync.commit(chain2.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d2.sync.idle();
    expect(await batchStatus(d2.storage, chain2.R, "op-1", 2n)).toMatchObject({
      status: "evidence-unavailable",
    });
  });

  it("is not accepted by a server off the Resource's route set", async () => {
    const server = new FakeServer();
    const chain = chainFor(223, "wss://elsewhere.example/v1/ws");
    serve(server, chain);
    const d = await device(server, chain);
    await d.live();
    await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d.sync.idle();
    expect(await batchStatus(d.storage, chain.R, "op-1", 2n)).toMatchObject({
      status: "evidence-unavailable",
      acceptedUnitIds: [],
    });
  });

  it("is rejected by a terminal NACK, with its code and units", async () => {
    const server = new FakeServer();
    const chain = chainFor(224);
    const srv = serve(server, chain);
    srv.put = ERROR_CODE.AUTHORIZATION_FAILED;
    const d = await device(server, chain);
    await d.live();
    const receipt = await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d.sync.idle();
    const b = await batchStatus(d.storage, chain.R, "op-1", 2n);
    expect(b?.status).toBe("rejected");
    expect(b?.rejection?.code).toBe("AUTHORIZATION_FAILED");
    expect(b?.rejection?.unitIds.map(toHex)).toEqual(receipt.unitIds.map(toHex));
    expect(kinds(d.events).at(-1)).toBe("batch:rejected");
  });
});

describe("pending again after a server loss (§4.2)", () => {
  it("reports the lost units as re-offered (have-gap) and accepts them again", async () => {
    const server = new FakeServer();
    const chain = chainFor(225);
    const srv = serve(server, chain);
    const d = await device(server, chain);
    await d.live();
    const receipt = await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d.sync.idle();
    expect((await batchStatus(d.storage, chain.R, "op-1", 2n))?.status).toBe("accepted");
    // The server is restored from a copy without the unit; anti-entropy finds the gap.
    srv.stored = [];
    srv.put = "silent";
    await d.at(31_000);
    const reoffered = d.events.find((e) => e.kind === "reoffered");
    expect(reoffered).toMatchObject({ kind: "reoffered", reason: "have-gap" });
    expect(reoffered?.kind === "reoffered" ? reoffered.unitIds.map(toHex) : []).toEqual(
      receipt.unitIds.map(toHex),
    );
    expect((await batchStatus(d.storage, chain.R, "op-1", 2n))?.status).toBe("pending");
    // The offer is acknowledged durably: accepted again, once.
    srv.put = "ack";
    await d.at(62_000);
    expect((await batchStatus(d.storage, chain.R, "op-1", 2n))?.status).toBe("accepted");
    expect(kinds(d.events)).toEqual([
      "access",
      "batch:pending",
      "batch:accepted",
      "batch:pending",
      "reoffered",
      "batch:accepted",
    ]);
  });
});

describe("statusSnapshot and the stream (§5)", () => {
  it("gives the complete state at the stream's revision, with section state and access", async () => {
    const server = new FakeServer();
    const chain = chainFor(226);
    serve(server, chain);
    const d = await device(server, chain);
    d.model.section = "importing";
    await d.live();
    await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    d.model.section = "ready";
    await d.sync.commit(chain.R, ["b"], { operationId: "op-2" });
    await settle(50);
    await d.sync.idle();
    const snap = await d.sync.statusSnapshot(chain.R);
    expect(snap.revision).toBe(d.events.at(-1)?.revision);
    expect(snap.batches.map((b) => [b.operationId, b.status])).toEqual([
      ["op-1", "accepted"],
      ["op-2", "accepted"],
    ]);
    expect(snap.section).toBe("ready");
    expect(snap.access).toMatchObject({ allowed: true, reason: null });
    expect(snap.received).toEqual({ held: [], waiting: [], refused: [] });
    expect(
      d.events
        .filter((e) => e.kind === "section-state")
        .map((e) => e.kind === "section-state" && e.state),
    ).toEqual(["importing", "ready"]);
  });
});

describe("received units (§4.3)", () => {
  it("reports held, waiting and refused units, and lists them in the snapshot", async () => {
    const server = new FakeServer();
    const chain = chainFor(227);
    const srv = serve(server, chain);
    // Units of another device of the owner, already on the server.
    const other = new InMemoryLfcpStorage();
    const v = chain.view();
    let previous: DataUnitId | null = null;
    for (const value of ["w", "h", "x"]) {
      const u: { unitId: DataUnitId; bytes: Uint8Array } = await createQueuedDataUnit(other, {
        view: v,
        controlHead: v.state.head,
        actor: OWNER.signer,
        dek: DEK0,
        profile: TEXT,
        previousUnitId: previous,
        value,
      });
      previous = u.unitId;
      srv.stored.push(u.bytes);
    }
    const d = await device(server, chain);
    await d.live();
    const received = d.events.filter((e) => e.kind === "received");
    expect(received.map((e) => e.kind === "received" && e.fact)).toEqual([
      "waiting",
      "held",
      "refused",
    ]);
    expect(received[2]).toMatchObject({ diagnostic: "refused: x is not a valid change" });
    const snap = await d.sync.statusSnapshot(chain.R);
    expect(snap.received.waiting).toHaveLength(1);
    expect(snap.received.held).toHaveLength(1);
    expect(snap.received.refused).toMatchObject([
      { diagnostic: "refused: x is not a valid change" },
    ]);
  });
});

describe("the loss signal's reason (§4.2)", () => {
  it("is unknown-previous when a later unit is refused naming the lost one", async () => {
    const server = new FakeServer();
    const chain = chainFor(228);
    const srv = serve(server, chain);
    const d = await device(server, chain);
    await d.live();
    const first = await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d.sync.idle();
    // The server loses the unit; the next one is refused with UNKNOWN_PREVIOUS.
    srv.stored = [];
    srv.put = ERROR_CODE.UNKNOWN_PREVIOUS;
    const onPut = server.onMessage;
    server.onMessage = (m, s) => {
      if (m.type === "DATA_PUT" && srv.put === ERROR_CODE.UNKNOWN_PREVIOUS) {
        srv.put = "ack";
        s.reply(m, "NACK", {
          code: ERROR_CODE.UNKNOWN_PREVIOUS,
          details: first.unitIds[0] as Uint8Array,
        });
        return [];
      }
      return onPut(m, s);
    };
    await d.sync.commit(chain.R, ["b"], { operationId: "op-2" });
    await settle(100);
    await d.sync.idle();
    const reoffered = d.events.filter((e) => e.kind === "reoffered");
    expect(reoffered).toMatchObject([{ kind: "reoffered", reason: "unknown-previous" }]);
    await d.at(1_000);
    await d.at(20_000);
    expect((await d.sync.statusSnapshot(chain.R)).batches.map((b) => b.status)).toEqual([
      "accepted",
      "accepted",
    ]);
  });

  it("is rehost when the route lost the Resource and the client hosted it again", async () => {
    const server = new FakeServer();
    const chain = chainFor(229);
    const srv = serve(server, chain);
    const d = await device(server, chain);
    await d.live();
    const receipt = await d.sync.commit(chain.R, ["a"], { operationId: "op-1" });
    await settle(50);
    await d.sync.idle();
    // The server is restored from a copy without the Resource.
    srv.stored = [];
    let hosted = false;
    const onHosted = server.onMessage;
    server.onMessage = (m, s) => {
      if (!hosted && m.type === "RESOURCE_OPEN") {
        s.reply(m, "NACK", { code: ERROR_CODE.RESOURCE_NOT_HOSTED });
        return [];
      }
      if (m.type === "RESOURCE_HOST") {
        hosted = true;
        s.reply(m, "RESOURCE_HOSTED", { resourceId: chain.R, durability: 2n });
        return [];
      }
      return onHosted(m, s);
    };
    server.current.drop();
    await settle(50);
    await d.at(1_000);
    await d.at(1_001);
    expect(d.sync.resourceState(chain.R)).toBe("LIVE");
    const status = d.events.filter((e) => e.kind !== "catch-up");
    const tail = status.slice(status.findIndex((e) => e.kind === "rehost"));
    expect(kinds(tail)).toEqual(["rehost", "batch:pending", "reoffered", "batch:accepted"]);
    expect(tail[2]).toMatchObject({ kind: "reoffered", reason: "rehost" });
    expect(tail[2]?.kind === "reoffered" && tail[2].unitIds.map(toHex)).toEqual(
      receipt.unitIds.map(toHex),
    );
  });
});

describe("Control freshness (LFCP-02-027)", () => {
  it("reports access as not current while the chain is behind the server, then current", async () => {
    const server = new FakeServer();
    const chain = chainFor(230);
    chain.add({
      type: "CAPABILITY_GRANT",
      subject: party(40).signer.descriptor,
      abilities: [1n],
      delegable: [],
    });
    serve(server, chain);
    const d = await device(server, chain, 1);
    await d.live();
    const access = d.events.flatMap((e) => (e.kind === "access" ? [e.access] : []));
    expect(access.map((a) => [a.controlSeq, a.serverControlSeq, a.current])).toEqual([
      [0n, 1n, false],
      [1n, 1n, true],
    ]);
    expect(access[1]?.verifiedAt).not.toBeNull();
  });
});

describe("catch-up (LFCP-02-028)", () => {
  it("is current at a checkpoint only once live, and stays so offline as of that check", async () => {
    const server = new FakeServer();
    const chain = chainFor(231);
    serve(server, chain);
    const d = await device(server, chain);
    expect((await d.sync.statusSnapshot(chain.R)).catchUp).toEqual({
      state: "not-started",
      checkedAt: null,
    });
    await d.at(5_000);
    await d.live();
    const catchUp = () =>
      d.events.flatMap((e) => (e.kind === "catch-up" ? [[e.state, e.checkedAt]] : []));
    expect(catchUp()).toEqual([
      ["receiving", null],
      ["current-at-checkpoint", 5_000],
    ]);
    server.current.drop();
    await settle(50);
    await d.sync.idle();
    // Offline: still current as of the last check, no new event.
    expect(catchUp()).toHaveLength(2);
    expect((await d.sync.statusSnapshot(chain.R)).catchUp).toEqual({
      state: "current-at-checkpoint",
      checkedAt: 5_000,
    });
    await d.at(7_000);
    await d.at(7_001);
    expect(catchUp().slice(2)).toEqual([
      ["receiving", 5_000],
      ["current-at-checkpoint", 7_000],
    ]);
  });
});

describe("the Snapshot policy (LFCP-02-097)", () => {
  it("counts the units this client commits, so a section's only writer reaches it", async () => {
    const server = new FakeServer();
    const chain = chainFor(232);
    serve(server, chain);
    const asked: number[] = [];
    const d = await device(server, chain, chain.records.length, (_, n) => {
      asked.push(n);
      return false;
    });
    await d.live();
    await d.sync.commit(chain.R, ["a", "b"], { operationId: "op-1" });
    await d.sync.commit(chain.R, ["c"], { operationId: "op-2" });
    await d.at(1_000);
    expect(asked.at(-1)).toBe(3);
  });
});

describe("revokeAccess refusals (LFCP-02-060)", () => {
  it("refuses while a Control Record of this client is pending, and queues nothing", async () => {
    const server = new FakeServer();
    const chain = chainFor(233);
    const bob = party(40);
    chain.add({
      type: "CAPABILITY_GRANT",
      subject: bob.signer.descriptor,
      abilities: [1n],
      delegable: [],
    });
    serve(server, chain);
    const d = await device(server, chain);
    await d.live();
    // A grant of ours still in flight: the server does not answer CONTROL_PUT here.
    const v = chain.view();
    const pending = signControlRecord(
      { resourceId: chain.R, controlSeq: v.state.seq + 1n, prevControlId: v.state.head },
      {
        type: "CAPABILITY_GRANT",
        subject: party(41).signer.descriptor,
        abilities: [1n],
        delegable: [],
      },
      OWNER.signer,
    );
    await queueControlRecord(d.storage, pending.bytes);
    const before = await d.storage.outbound.list(chain.R);
    expect(await d.sync.revokeAccess(chain.R, bob.signer.descriptor.principalId)).toMatchObject({
      kind: "refused",
      reason: "control-pending",
    });
    expect(await d.storage.outbound.list(chain.R)).toEqual(before);
  });
});
