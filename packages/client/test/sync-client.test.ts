import {
  type ControlRecordId,
  dataEpoch,
  type ResourceId,
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
  principalDescriptorFromKeys,
  rotateEpoch,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import {
  createQueuedDataUnit,
  type DataProfileHandler,
  DataUnitApplier,
  dekResolver,
  OutboundQueue,
  SyncClient,
  type SyncEvent,
  saveControlChain,
} from "../src/index.js";
import { FakeServer, settle } from "./fake-server.js";

// SyncClient against a scripted fake server (the real Rust server runs in
// conformance/interop). Time is a variable the test moves.

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const party = (seed: number): { signer: Signer; agreement: AgreementKeyPair } => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const OWNER = party(1);
const BOB = party(41);
const PROFILE = "org.example.text.v1";
const DEK0 = importResourceDEK(bytes32(90));
const DEK1 = importResourceDEK(bytes32(91));

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const TEXT: DataProfileCodec<string> = {
  dataProfile: PROFILE,
  encode: ascii,
  decode: (p) => String.fromCharCode(...p),
};

/** A Resource's records: Genesis by OWNER, then whatever the test adds. */
function chainFor(seed: number) {
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
    return s;
  };
  add({
    type: "GENESIS",
    dataProfile: PROFILE,
    owner: OWNER.signer.descriptor,
    dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
    endpoints: [{ url: "ws://127.0.0.1:1/v1/ws", priority: 0n }],
    coordinatorUrl: "ws://127.0.0.1:1/v1/ws",
  });
  const view = () => {
    const r = validateControlChain(records);
    if (r.kind !== "linear") throw new Error(r.kind);
    return r;
  };
  return { R, records, ids, add, view };
}

/** A client of `who` with the text profile; `merged` collects applied values. */
function client(
  who: { signer: Signer; agreement: AgreementKeyPair },
  server: FakeServer,
  clock: { t: number },
) {
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
  const merged: string[] = [];
  const handler: DataProfileHandler<string> = {
    dataProfile: PROFILE,
    codecFor: () => TEXT,
    apply: (u, v) => {
      merged.push(v);
      return { merged: [u.unitId], objects: [], diagnostics: [] };
    },
    exclude: () => ({ objects: [], pending: [] }),
  };
  const events: SyncEvent[] = [];
  const outbound = new OutboundQueue({ storage });
  const sync = new SyncClient({
    url: "ws://127.0.0.1:1/v1/ws",
    signer: who.signer,
    agreement: who.agreement,
    storage,
    secrets,
    outbound,
    now: () => clock.t,
    webSocket: server.factory,
    reconnect: () => 1000,
  });
  sync.on((e) => events.push(e));
  const binding = (R: ResourceId) => ({
    resourceId: R,
    applier: new DataUnitApplier({
      storage,
      dek: dekResolver(storage, secrets, R),
      handlers: [handler as DataProfileHandler<unknown>],
    }),
  });
  return { storage, secrets, merged, events, outbound, sync, binding };
}

/** OWNER's local state: the chain and the epoch-0 DEK. */
async function ownerState(c: ReturnType<typeof client>, chain: ReturnType<typeof chainFor>) {
  await saveControlChain(c.storage, chain.view(), null);
  await c.secrets.put(dekSecretRef(chain.R, dataEpoch(0n)), exportSecretKeyBytes(DEK0));
  const e0 = (await c.storage.control.epochs(chain.R))[0] as EpochRow;
  await c.storage.commit([
    {
      op: "put-epoch",
      resourceId: chain.R,
      epoch: { ...e0, dekRef: dekSecretRef(chain.R, dataEpoch(0n)) },
    },
  ]);
}

/** A server that answers like a host of `chain` with `units` (exact bytes). */
function hostOf(
  server: FakeServer,
  chain: ReturnType<typeof chainFor>,
  units: Uint8Array[] = [],
  packages: Uint8Array[] = [],
) {
  server.onMessage = (m, s) => {
    const reply = (type: AnyMessage["type"], body: unknown) =>
      s.reply(m, type as never, body as never);
    const v = chain.view();
    switch (m.type) {
      case "RESOURCE_OPEN":
        reply("RESOURCE_OPENED", {
          resourceId: chain.R,
          heads: [{ seq: v.state.seq, recordId: v.state.head }],
          haves:
            units.length === 0
              ? []
              : [
                  {
                    principalId: OWNER.signer.descriptor.principalId,
                    contiguous: BigInt(units.length),
                  },
                ],
        });
        break;
      case "CONTROL_GET":
        reply("CONTROL_BATCH", {
          resourceId: chain.R,
          objects: chain.records.slice(Number(m.body.start), Number(m.body.end) + 1),
        });
        break;
      case "KEY_PACKAGE_GET":
        reply("KEY_PACKAGE_BATCH", { resourceId: chain.R, objects: packages });
        break;
      case "DATA_GET":
        reply("DATA_BATCH", { resourceId: chain.R, objects: units });
        break;
      case "DATA_PUT":
        reply("ACK", { requestType: 33n, objectIds: [] });
        break;
    }
    return [];
  };
}

const states = (events: SyncEvent[]) =>
  events.filter((e) => e.type === "resource-state").map((e) => (e as { state: string }).state);

describe("SyncClient (LFCP-039a) on a fake server", () => {
  it("opens with live subscriptions, syncs Control, Keys and Data, and goes LIVE", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(200);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const v = chain.view();
    const u = await createQueuedDataUnit(new InMemoryLfcpStorage(), {
      view: v,
      controlHead: v.state.head,
      actor: OWNER.signer,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: null,
      value: "hello",
    });
    hostOf(server, chain, [u.bytes]);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    const open = server.of("RESOURCE_OPEN")[0];
    expect(open?.body.flags).toBe(3n);
    expect(open?.body.heads.map((h) => h.seq)).toEqual([0n]);
    expect(states(owner.events)).toEqual([
      "OPENING",
      "CONTROL_SYNC",
      "KEY_SYNC",
      "DATA_SYNC",
      "LIVE",
    ]);
    expect(server.of("KEY_PACKAGE_GET")).toEqual([]); // the owner holds its DEK
    expect(owner.merged).toEqual(["hello"]);
  });

  it("closes every Resource when the connection is lost and reconnects on the policy's schedule", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(201);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    hostOf(server, chain);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    server.current.drop();
    await settle(50);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("CLOSED");
    expect(owner.sync.connectionState).toBe("DISCONNECTED");
    owner.sync.tick(500);
    expect(server.sockets).toHaveLength(1);
    clock.t = 1000;
    owner.sync.tick(1000);
    await settle(200);
    await owner.sync.idle();
    expect(server.sockets).toHaveLength(2);
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    expect(server.of("RESOURCE_OPEN")).toHaveLength(2);
  });

  it("enters CONTROL_CONFLICT on competing records and never resolves it (§42, §67)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(202);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const a = signControlRecord(
      { resourceId: chain.R, controlSeq: 1n, prevControlId: chain.ids[0] as ControlRecordId },
      { type: "CAPABILITY_GRANT", subject: BOB.signer.descriptor, abilities: [1n], delegable: [] },
      OWNER.signer,
    );
    const b = signControlRecord(
      { resourceId: chain.R, controlSeq: 1n, prevControlId: chain.ids[0] as ControlRecordId },
      {
        type: "CAPABILITY_GRANT",
        subject: BOB.signer.descriptor,
        abilities: [1n, 2n],
        delegable: [],
      },
      OWNER.signer,
    );
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN")
        s.reply(m, "RESOURCE_OPENED", {
          resourceId: chain.R,
          heads: [
            { seq: 1n, recordId: a.recordId },
            { seq: 1n, recordId: b.recordId },
          ],
          haves: [],
        });
      if (m.type === "CONTROL_GET")
        s.reply(m, "CONTROL_BATCH", { resourceId: chain.R, objects: [a.bytes, b.bytes] });
      return [];
    };
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("CONTROL_CONFLICT");
    const conflict = owner.events.find((e) => e.type === "control-conflict");
    expect(conflict?.type === "control-conflict" && conflict.heads.map(toHex).sort()).toEqual(
      [a.recordId, b.recordId].map(toHex).sort(),
    );
    expect((await owner.storage.control.conflict(chain.R))?.heads).toHaveLength(2);
    expect((await owner.storage.control.head(chain.R))?.controlSeq).toBe(0n);
  });

  it("blocks on a missing Key Package and continues when it arrives (KEY_BLOCKED)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(203);
    const grant = chain.add({
      type: "CAPABILITY_GRANT",
      subject: BOB.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    });
    const bob = client(BOB, server, clock);
    const packages: Uint8Array[] = [];
    hostOf(server, chain, [], packages);
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    await settle(200);
    await bob.sync.idle();
    expect(bob.sync.resourceState(chain.R)).toBe("KEY_BLOCKED");
    expect(bob.events.some((e) => e.type === "key-blocked")).toBe(true);
    expect(server.of("KEY_PACKAGE_GET")[0]?.body.epochs).toEqual([0n]);
    const kp = await sealKeyPackage({
      resourceId: chain.R,
      epoch: dataEpoch(0n),
      controlHead: grant.recordId,
      recipient: BOB.signer.descriptor,
      dek: DEK0,
      signer: OWNER.signer,
    });
    packages.push(kp.bytes);
    clock.t = 30_000; // the retry interval
    bob.sync.tick(clock.t);
    await settle(200);
    await bob.sync.idle();
    expect(bob.sync.resourceState(chain.R)).toBe("LIVE");
    expect(await dekResolver(bob.storage, bob.secrets, chain.R)(dataEpoch(0n))).toBeDefined();
  });

  it("fetches missing ranges when the server's Have is ahead while LIVE (§69)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(204);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const units: Uint8Array[] = [];
    hostOf(server, chain, units);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    const v = chain.view();
    const u = await createQueuedDataUnit(new InMemoryLfcpStorage(), {
      view: v,
      controlHead: v.state.head,
      actor: OWNER.signer,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: null,
      value: "late",
    });
    units.push(u.bytes);
    server.push({
      type: "DATA_HAVE",
      messageId: new Uint8Array(16).fill(3),
      body: {
        resourceId: chain.R,
        haves: [{ principalId: OWNER.signer.descriptor.principalId, contiguous: 1n }],
      },
    });
    await settle(200);
    await owner.sync.idle();
    expect(server.of("DATA_GET")[0]?.body.ranges.map((r) => [r.start, r.end])).toEqual([[1n, 1n]]);
    expect(owner.merged).toEqual(["late"]);
    expect(states(owner.events).slice(-2)).toEqual(["DATA_SYNC", "LIVE"]);
  });

  it("on a new Key Epoch reconciles both the applier and the queue (G-EP7, §88 step 7)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(205);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    hostOf(server, chain);
    // Two units of ours queued while offline; the server only ever ACKs nothing.
    const v = chain.view();
    const u1 = await createQueuedDataUnit(owner.storage, {
      view: v,
      controlHead: v.state.head,
      actor: OWNER.signer,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: null,
      value: "one",
    });
    await createQueuedDataUnit(owner.storage, {
      view: v,
      controlHead: v.state.head,
      actor: OWNER.signer,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: u1.unitId,
      value: "two",
    });
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    // A Key Epoch closes epoch 0 with OWNER's frontier at sequence 1, pushed live.
    const rotation = rotateEpoch(chain.view().state, OWNER.signer, {
      reason: 1n,
      finalFrontier: [
        { principalId: OWNER.signer.descriptor.principalId, contiguous: 1n, extras: [] },
      ],
      dek: DEK1,
    });
    chain.records.push(rotation.bytes);
    chain.ids.push(rotation.recordId);
    server.push({
      type: "CONTROL_BATCH",
      messageId: new Uint8Array(16).fill(4),
      body: { resourceId: chain.R, objects: [rotation.bytes] },
    });
    await settle(300);
    await owner.sync.idle();
    const reconciled = owner.events.find((e) => e.type === "epoch-reconciled");
    expect(
      reconciled?.type === "epoch-reconciled" && reconciled.outbound.map((s) => s.seq),
    ).toEqual([2n]);
    expect(
      reconciled?.type === "epoch-reconciled" &&
        reconciled.applied.excluded.map((x) => x.quarantine.reason),
    ).toEqual(["BEYOND_CUTOFF"]);
    expect((await owner.storage.control.head(chain.R))?.controlSeq).toBe(1n);
    // Epoch 1's DEK is not held: KEY_BLOCKED for the new epoch, surfaced.
    expect(owner.sync.resourceState(chain.R)).toBe("KEY_BLOCKED");
    expect(
      (await owner.storage.outbound.list(chain.R)).map((o) => o.blocked?.reason ?? null),
    ).toEqual([null, "stale-epoch"]);
  });

  it("surfaces a refused RESOURCE_OPEN and leaves the Resource CLOSED", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(206);
    const bob = client(BOB, server, clock);
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN") s.reply(m, "NACK", { code: 6n, diagnostic: "not hosted" });
      return [];
    };
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    await settle(200);
    await bob.sync.idle();
    expect(bob.sync.resourceState(chain.R)).toBe("CLOSED");
    expect(bob.events.find((e) => e.type === "error")).toMatchObject({ code: "NACK 6" });
  });
});
