import {
  type ControlRecordId,
  dataEpoch,
  hash32,
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
  sha256 as sha,
} from "@openlfcp/crypto";
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  InMemorySecretStore,
  InMemorySnapshotSequenceReservation,
} from "@openlfcp/storage";
import {
  type AnyMessage,
  type ControlBody,
  createMessage,
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
  createSnapshot,
  type DataProfileHandler,
  DataUnitApplier,
  dekResolver,
  OutboundQueue,
  queueControlRecord,
  queueKeyEpoch,
  queueKeyPackage,
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
  /** The device's stores, to start again on them (a restart). */
  device?: { storage: InMemoryLfcpStorage; secrets: InMemorySecretStore },
) {
  const storage = device?.storage ?? new InMemoryLfcpStorage();
  const secrets = device?.secrets ?? new InMemorySecretStore();
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

  it("asks for at most 256 epochs per KEY_PACKAGE_GET, the newest first (§52)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(209);
    chain.add({
      type: "CAPABILITY_GRANT",
      subject: BOB.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    });
    for (let e = 1n; e < 300n; e++)
      chain.add({
        type: "KEY_EPOCH",
        epoch: dataEpoch(e),
        dekCommitment: dekCommitment(chain.R, dataEpoch(e), DEK1),
        finalFrontier: [],
        reason: 0n,
      });
    const bob = client(BOB, server, clock);
    hostOf(server, chain, [], []);
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    for (let i = 0; i < 40 && server.of("KEY_PACKAGE_GET").length === 0; i++) {
      await settle(100);
      await bob.sync.idle();
    }
    const epochs = server.of("KEY_PACKAGE_GET")[0]?.body.epochs ?? [];
    expect(epochs).toHaveLength(256);
    expect([epochs[0], epochs.at(-1)]).toEqual([44n, 299n]);
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
    // §86: the package is kept with the Resource, to re-supply a server that lost it (§68.1).
    expect((await bob.storage.keyPackages.list(chain.R)).map((k) => k.bytes)).toEqual([kp.bytes]);
  });

  it("issues a data round again when its DATA_GET reply is lost on a live connection (§70)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(205);
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
      value: "late reply",
    });
    hostOf(server, chain, [u.bytes]);
    const answer = server.onMessage;
    let swallowed = 0;
    server.onMessage = (m, s) => {
      if (m.type === "DATA_GET" && swallowed === 0) {
        swallowed++; // the reply is lost; the connection stays up
        return [];
      }
      return answer(m, s);
    };
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("DATA_SYNC");
    clock.t = 14_999;
    owner.sync.tick(clock.t);
    await settle(50);
    expect(server.of("DATA_GET")).toHaveLength(1);
    clock.t = 15_000;
    owner.sync.tick(clock.t);
    await settle(200);
    await owner.sync.idle();
    expect(server.of("DATA_GET")).toHaveLength(2);
    expect(server.sockets).toHaveLength(1); // no reconnect
    expect(owner.merged).toEqual(["late reply"]);
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
  });

  it("falls back to the data round when the offered Snapshot is lost or refused (§29.2, §70)", async () => {
    for (const fault of ["lost", "nack"] as const) {
      const server = new FakeServer();
      const clock = { t: 0 };
      const chain = chainFor(fault === "lost" ? 206 : 207);
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
        value: "from units",
      });
      const frontier = [{ principalId: OWNER.signer.descriptor.principalId, contiguous: 1n }];
      const snapshot = await createSnapshot({
        view: v,
        controlHead: v.state.head,
        publisher: OWNER.signer,
        dek: DEK0,
        frontier,
        profile: TEXT,
        value: "from the snapshot",
        sequences: new InMemorySnapshotSequenceReservation(),
      });
      hostOf(server, chain, [u.bytes]);
      const answer = server.onMessage;
      server.onMessage = (m, sv) => {
        if (m.type === "RESOURCE_OPEN") {
          sv.reply(m, "RESOURCE_OPENED", {
            resourceId: chain.R,
            heads: [{ seq: v.state.seq, recordId: v.state.head }],
            haves: frontier,
            snapshot: { snapshotId: snapshot.snapshotId, dataEpoch: 0n, frontier },
          });
          return [];
        }
        if (m.type === "SNAPSHOT_GET") {
          if (fault === "nack")
            sv.reply(m, "NACK", { code: 15n, diagnostic: "MISSING_DEPENDENCY" });
          return []; // "lost": no answer at all
        }
        return answer(m, sv);
      };
      const loaded: string[] = [];
      const binding = {
        ...owner.binding(chain.R),
        snapshot: {
          codec: TEXT,
          load: (value: unknown) => void loaded.push(value as string),
          current: () => "",
        },
      };
      owner.sync.open(binding);
      owner.sync.start();
      await settle(200);
      await owner.sync.idle();
      expect(server.of("SNAPSHOT_GET")).toHaveLength(1);
      if (fault === "lost") {
        expect(server.of("DATA_GET")).toEqual([]); // still waiting for the Snapshot
        clock.t = 15_000;
        owner.sync.tick(clock.t);
        await settle(200);
        await owner.sync.idle();
      }
      expect(server.of("DATA_GET")).toHaveLength(1);
      expect(loaded).toEqual([]);
      expect(owner.merged).toEqual(["from units"]);
      expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
      expect(server.sockets).toHaveLength(1);
    }
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

  it("a DATA_HAVE spanning 2^64 - 1 sequences costs intervals, not sequences (H2)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(206);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    hostOf(server, chain);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    const MAX = 2n ** 64n - 1n;
    const t0 = performance.now();
    server.push({
      type: "DATA_HAVE",
      messageId: new Uint8Array(16).fill(4),
      body: {
        resourceId: chain.R,
        haves: [{ principalId: OWNER.signer.descriptor.principalId, contiguous: MAX }],
      },
    });
    await settle(200);
    await owner.sync.idle();
    expect(performance.now() - t0).toBeLessThan(2_000);
    expect(server.of("DATA_GET")[0]?.body.ranges.map((r) => [r.start, r.end])).toEqual([[1n, MAX]]);
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

  /**
   * A coordinator for `chain` that commits CONTROL_PUTs: `hold` (by the
   * record's sequence) delays a put's commit and ACK until the next
   * CONTROL_HAVE has been answered, as when a put lands just after the
   * server read its heads.
   */
  function coordinatorOf(server: FakeServer, chain: ReturnType<typeof chainFor>, hold = -1n) {
    hostOf(server, chain);
    const host = server.onMessage;
    const held: AnyMessage[] = [];
    const commit = (m: Extract<AnyMessage, { type: "CONTROL_PUT" }>, s: FakeServer) => {
      const r = validateControlChain([...chain.records, m.body.record]);
      if (r.kind !== "linear") throw new Error(r.kind);
      chain.records.push(m.body.record);
      chain.ids.push(r.state.head);
      s.reply(m, "ACK", { requestType: 23n, objectIds: [hash32(r.state.head)], durable: true });
    };
    server.onMessage = (m, s) => {
      if (m.type === "CONTROL_PUT") {
        if (BigInt(chain.records.length) === hold) held.push(m);
        else commit(m, s);
        return [];
      }
      if (m.type === "CONTROL_HAVE") {
        const v = chain.view();
        s.reply(m, "CONTROL_HAVE", {
          resourceId: chain.R,
          heads: [{ seq: v.state.seq, recordId: v.state.head }],
        });
        for (const h of held.splice(0))
          commit(h as Extract<AnyMessage, { type: "CONTROL_PUT" }>, s);
        return [];
      }
      return host(m, s);
    };
  }

  it("the owner of a new Key Epoch holds its DEK with no Key Package round trip", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(210);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    coordinatorOf(server, chain);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    const rotation = rotateEpoch(chain.view().state, OWNER.signer, {
      reason: 0n,
      finalFrontier: [],
    });
    await queueKeyEpoch(owner.storage, owner.secrets, rotation);
    owner.sync.flush();
    await settle(300);
    await owner.sync.idle();
    expect((await owner.storage.control.head(chain.R))?.controlSeq).toBe(1n);
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    expect(server.of("KEY_PACKAGE_GET")).toEqual([]);
    const dek = await dekResolver(owner.storage, owner.secrets, chain.R)(rotation.epoch);
    expect(dek).toBeDefined();
    expect(toHex(dekCommitment(chain.R, rotation.epoch, dek as never))).toBe(
      toHex(rotation.dekCommitment),
    );
  });

  it("learns its own record committed during a Control sync once LIVE again (no lost refresh)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(211);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    // The rotation (sequence 2) commits only after the server answered the
    // CONTROL_HAVE that the grant's (sequence 1) ACK triggered.
    coordinatorOf(server, chain, 2n);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    const grant = signControlRecord(
      { resourceId: chain.R, controlSeq: 1n, prevControlId: chain.ids[0] as ControlRecordId },
      { type: "CAPABILITY_GRANT", subject: BOB.signer.descriptor, abilities: [1n], delegable: [] },
      OWNER.signer,
    );
    const afterGrant = validateControlChain([...chain.records, grant.bytes]);
    if (afterGrant.kind !== "linear") throw new Error(afterGrant.kind);
    const rotation = rotateEpoch(afterGrant.state, OWNER.signer, { reason: 0n, finalFrontier: [] });
    await queueControlRecord(owner.storage, grant.bytes);
    await queueKeyEpoch(owner.storage, owner.secrets, rotation);
    owner.sync.flush();
    await settle(500);
    await owner.sync.idle();
    expect(chain.records).toHaveLength(3); // both committed on the server
    expect((await owner.storage.control.head(chain.R))?.controlSeq).toBe(2n);
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    expect(await dekResolver(owner.storage, owner.secrets, chain.R)(rotation.epoch)).toBeDefined();
    expect(server.of("KEY_PACKAGE_GET")).toEqual([]);
  });

  it("uses a DEK stored before its epoch row as soon as the row is saved", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(212);
    chain.add({
      type: "CAPABILITY_GRANT",
      subject: BOB.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    });
    const bob = client(BOB, server, clock);
    // A Key Package's DEK stored before the chain (the row) existed here.
    await bob.secrets.put(dekSecretRef(chain.R, dataEpoch(0n)), exportSecretKeyBytes(DEK0));
    hostOf(server, chain);
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    await settle(200);
    await bob.sync.idle();
    expect(bob.sync.resourceState(chain.R)).toBe("LIVE");
    expect(server.of("KEY_PACKAGE_GET")).toEqual([]);
    expect((await bob.storage.control.epochs(chain.R))[0]?.dekRef).toBe(
      dekSecretRef(chain.R, dataEpoch(0n)),
    );
  });

  it("never adopts a stored DEK that does not match the epoch's commitment", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(213);
    chain.add({
      type: "CAPABILITY_GRANT",
      subject: BOB.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    });
    const bob = client(BOB, server, clock);
    await bob.secrets.put(dekSecretRef(chain.R, dataEpoch(0n)), exportSecretKeyBytes(DEK1));
    hostOf(server, chain);
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    await settle(200);
    await bob.sync.idle();
    expect(bob.sync.resourceState(chain.R)).toBe("KEY_BLOCKED");
    expect((await bob.storage.control.epochs(chain.R))[0]?.dekRef).toBeNull();
  });

  it("never loads again a Snapshot that crashed the engine twice (crash-loop breaker)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(214);
    const first = client(OWNER, server, clock);
    await ownerState(first, chain);
    const v = chain.view();
    const u = await createQueuedDataUnit(new InMemoryLfcpStorage(), {
      view: v,
      controlHead: v.state.head,
      actor: OWNER.signer,
      dek: DEK0,
      profile: TEXT,
      previousUnitId: null,
      value: "from units",
    });
    const frontier = [{ principalId: OWNER.signer.descriptor.principalId, contiguous: 1n }];
    const snapshot = await createSnapshot({
      view: v,
      controlHead: v.state.head,
      publisher: OWNER.signer,
      dek: DEK0,
      frontier,
      profile: TEXT,
      value: "poison",
      sequences: new InMemorySnapshotSequenceReservation(),
    });
    hostOf(server, chain, [u.bytes]);
    const answer = server.onMessage;
    server.onMessage = (m, sv) => {
      if (m.type === "RESOURCE_OPEN") {
        sv.reply(m, "RESOURCE_OPENED", {
          resourceId: chain.R,
          heads: [{ seq: v.state.seq, recordId: v.state.head }],
          haves: frontier,
          snapshot: { snapshotId: snapshot.snapshotId, dataEpoch: 0n, frontier },
        });
        return [];
      }
      if (m.type === "SNAPSHOT_GET") {
        sv.reply(m, "SNAPSHOT", { resourceId: chain.R, snapshot: snapshot.bytes });
        return [];
      }
      return answer(m, sv);
    };
    const run = async (c: ReturnType<typeof client>) => {
      const binding = {
        ...c.binding(chain.R),
        snapshot: {
          codec: TEXT,
          load: () => {
            throw new WebAssembly.RuntimeError("unreachable executed"); // the engine traps
          },
          current: () => "",
        },
      };
      c.sync.open(binding);
      c.sync.start();
      await settle(200);
      await c.sync.idle();
      await c.sync.stop();
    };
    // Two starts trap while loading it; the third never asks for it again.
    await run(first);
    expect(server.of("SNAPSHOT_GET")).toHaveLength(1);
    // The trap stops this client once, with ENGINE_TRAP, and it stays stopped.
    expect(first.events.filter((e) => e.type === "error").map((e) => e.code)).toEqual([
      "ENGINE_TRAP",
    ]);
    await run(client(OWNER, server, clock, first));
    expect(server.of("SNAPSHOT_GET")).toHaveLength(2);
    const third = client(OWNER, server, clock, first);
    await run(third);
    expect(server.of("SNAPSHOT_GET")).toHaveLength(2);
    expect(third.merged).toEqual(["from units"]);
    expect(
      third.events.some((e) => e.type === "error" && e.code === "INVALID_AUTOMERGE_BYTES"),
    ).toBe(true);
  });

  it("RESOURCE_NOT_HOSTED is a terminal refusal: CLOSED, an event, no retry until open() asks again (POST-017)", async () => {
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
    const refusal = {
      code: "RESOURCE_NOT_HOSTED",
      diagnostic: "not hosted",
      url: "ws://127.0.0.1:1/v1/ws",
      request: "open",
    };
    expect(bob.sync.resourceRefusal(chain.R)).toEqual(refusal);
    expect(bob.events.filter((e) => e.type === "resource-refused")).toEqual([
      { type: "resource-refused", resourceId: chain.R, refusal },
    ]);
    // The error event stays for applications that only log errors.
    expect(bob.events.find((e) => e.type === "error")).toMatchObject({
      code: "RESOURCE_NOT_HOSTED",
    });
    // No retry on the clock …
    for (let i = 0; i < 5; i++) {
      clock.t += 60_000;
      bob.sync.tick(clock.t);
      await settle(20);
    }
    await bob.sync.idle();
    expect(server.of("RESOURCE_OPEN")).toHaveLength(1);
    // … nor after a reconnect.
    server.current.drop();
    await settle(50);
    clock.t += 2000;
    bob.sync.tick(clock.t);
    await settle(200);
    await bob.sync.idle();
    expect(server.sockets).toHaveLength(2);
    expect(bob.sync.connectionState).toBe("READY");
    expect(server.of("RESOURCE_OPEN")).toHaveLength(1);
    // An explicit open asks the server again.
    bob.sync.open(bob.binding(chain.R));
    expect(bob.sync.resourceRefusal(chain.R)).toBeNull();
    await settle(200);
    await bob.sync.idle();
    expect(server.of("RESOURCE_OPEN")).toHaveLength(2);
    expect(bob.sync.resourceRefusal(chain.R)).toEqual(refusal);
  });

  it("access recovery after AUTHORIZATION_FAILED tolerates a bounded number of transient refusals (LFCP-02-106)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(209);
    chain.add({
      type: "CAPABILITY_GRANT",
      subject: BOB.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    });
    const bob = client(BOB, server, clock);
    await saveControlChain(bob.storage, chain.view(), null);
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN") s.reply(m, "NACK", { code: 4n }); // AUTHORIZATION_FAILED
      if (m.type === "CONTROL_PUT") s.reply(m, "NACK", { code: 17n }); // RATE_LIMITED
      return [];
    };
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    await settle(200);
    await bob.sync.idle();
    // The grant is pushed, expecting the Genesis.
    const put = server.of("CONTROL_PUT")[0];
    expect(toHex(put?.body.expectedHead as Uint8Array)).toBe(toHex(chain.ids[0] as Uint8Array));
    for (let i = 0; i < 5; i++) {
      clock.t += 1000;
      bob.sync.tick(clock.t);
      await settle(100);
      await bob.sync.idle();
    }
    // One push and three retries after RATE_LIMITED, then the refusal stands.
    expect(server.of("CONTROL_PUT")).toHaveLength(4);
    expect(server.of("RESOURCE_OPEN")).toHaveLength(4);
    expect(bob.sync.resourceRefusal(chain.R)?.code).toBe("AUTHORIZATION_FAILED");
    const outcomes = bob.events.flatMap((e) =>
      e.type === "access-recovery" ? [`${e.outcome}${e.reason ? `:${e.reason}` : ""}`] : [],
    );
    expect(outcomes.at(-1)).toBe("ended:refused");
  });

  it("a transient refusal of the open is retried with backoff instead of waiting for a reconnect", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(208);
    const bob = client(BOB, server, clock);
    const codes = [22n, 17n, 6n]; // INTERNAL_ERROR, RATE_LIMITED, then RESOURCE_NOT_HOSTED
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN") s.reply(m, "NACK", { code: codes.shift() ?? 6n });
      return [];
    };
    bob.sync.open(bob.binding(chain.R));
    bob.sync.start();
    await settle(200);
    await bob.sync.idle();
    expect(server.of("RESOURCE_OPEN")).toHaveLength(1);
    expect(bob.sync.resourceRefusal(chain.R)).toBeNull();
    // Not before the backoff (the test policy: 1000 ms) …
    clock.t += 500;
    bob.sync.tick(clock.t);
    await settle(50);
    expect(server.of("RESOURCE_OPEN")).toHaveLength(1);
    // … then again, on the same connection.
    for (const expected of [2, 3]) {
      clock.t += 1000;
      bob.sync.tick(clock.t);
      await settle(100);
      await bob.sync.idle();
      expect(server.of("RESOURCE_OPEN")).toHaveLength(expected);
    }
    expect(server.sockets).toHaveLength(1);
    expect(bob.sync.resourceRefusal(chain.R)?.code).toBe("RESOURCE_NOT_HOSTED");
    clock.t += 10_000;
    bob.sync.tick(clock.t);
    await settle(50);
    expect(server.of("RESOURCE_OPEN")).toHaveLength(3);
  });

  it("AUTHORIZATION_FAILED on a read mid-sync (a revoked reader) refuses the Resource and closes it", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(209);
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
    const host = server.onMessage;
    server.onMessage = (m, s) => {
      if (m.type !== "DATA_GET") return host(m, s);
      s.reply(m, "NACK", { code: 4n });
      return [];
    };
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("CLOSED");
    expect(owner.sync.resourceRefusal(chain.R)).toMatchObject({
      code: "AUTHORIZATION_FAILED",
      request: "data-get",
    });
    expect(server.of("RESOURCE_CLOSE")).toHaveLength(1);
    clock.t += 120_000;
    owner.sync.tick(clock.t);
    await settle(50);
    expect(server.of("RESOURCE_OPEN")).toHaveLength(1);
  });

  it("names the §62 code of a refused RESOURCE_HOST", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(207);
    const owner = client(OWNER, server, clock);
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_HOST") s.reply(m, "NACK", { code: 20n });
      return [];
    };
    owner.sync.start();
    await settle(200);
    await expect(owner.sync.host(chain.records[0] as Uint8Array)).rejects.toThrow(
      "RESOURCE_HOST refused: NACK HOSTING_DENIED",
    );
  });

  /** OWNER's acknowledged units 1..n (stored as accepted, no longer queued). */
  async function ackedUnits(
    c: ReturnType<typeof client>,
    chain: ReturnType<typeof chainFor>,
    values: readonly string[],
  ) {
    const v = chain.view();
    const out: { unitId: Uint8Array; bytes: Uint8Array }[] = [];
    for (const value of values) {
      const u = await createQueuedDataUnit(c.storage, {
        view: v,
        controlHead: v.state.head,
        actor: OWNER.signer,
        dek: DEK0,
        profile: TEXT,
        previousUnitId: (out.at(-1)?.unitId as never) ?? null,
        value,
      });
      out.push(u);
    }
    return out;
  }

  const dequeue = (c: ReturnType<typeof client>, ids: readonly Uint8Array[]) =>
    c.storage.commit(ids.map((id) => ({ op: "dequeue" as const, itemId: hash32(id) })));

  it("offers a restored server the Control Records, units and Key Packages it lacks (§68.1)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(208);
    const grant = chain.add({
      type: "CAPABILITY_GRANT",
      subject: BOB.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    });
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const units = await ackedUnits(owner, chain, ["one", "two", "three"]);
    const kp = await sealKeyPackage({
      resourceId: chain.R,
      epoch: dataEpoch(0n),
      controlHead: grant.recordId,
      recipient: BOB.signer.descriptor,
      dek: DEK0,
      signer: OWNER.signer,
    });
    const kpId = await queueKeyPackage(owner.storage, kp.bytes);
    await dequeue(owner, [...units.map((u) => u.unitId), kpId]);
    // The server was restored from a copy holding the Genesis and units 1..2.
    server.onMessage = (m, s) => {
      const reply = (type: AnyMessage["type"], body: unknown) =>
        s.reply(m, type as never, body as never);
      if (m.type === "RESOURCE_OPEN")
        reply("RESOURCE_OPENED", {
          resourceId: chain.R,
          heads: [{ seq: 0n, recordId: chain.ids[0] }],
          haves: [{ principalId: OWNER.signer.descriptor.principalId, contiguous: 2n }],
        });
      else if (m.type === "CONTROL_PUT") reply("ACK", { requestType: 26n, objectIds: [] });
      else if (m.type === "DATA_PUT") reply("ACK", { requestType: 33n, objectIds: [] });
      else if (m.type === "KEY_PACKAGE_PUT") reply("ACK", { requestType: 36n, objectIds: [] });
      return [];
    };
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    const puts = server.received.filter((m) =>
      ["CONTROL_PUT", "DATA_PUT", "KEY_PACKAGE_PUT"].includes(m.type),
    );
    expect(puts.map((m) => m.type)).toEqual(["CONTROL_PUT", "KEY_PACKAGE_PUT", "DATA_PUT"]);
    const control = server.of("CONTROL_PUT")[0];
    expect(control?.body.record).toEqual(chain.records[1]);
    expect(toHex(control?.body.expectedHead as Uint8Array)).toBe(toHex(chain.ids[0] as Uint8Array));
    expect(server.of("DATA_PUT")[0]?.body.objects).toEqual([units[2]?.bytes]);
    expect(server.of("KEY_PACKAGE_PUT")[0]?.body.objects).toEqual([kp.bytes]);
    expect(owner.events.filter((e) => e.type === "error" || e.type === "nack")).toEqual([]);
    // A server that lacks nothing is offered nothing.
    server.received.length = 0;
    server.push(
      createMessage("DATA_HAVE", {
        resourceId: chain.R,
        haves: [{ principalId: OWNER.signer.descriptor.principalId, contiguous: 3n }],
      }),
    );
    await settle(100);
    await owner.sync.idle();
    expect(server.of("DATA_PUT")).toEqual([]);
  });

  it("an offered unit refused as equivocation is no alarm; a refused batch is split (§68.1)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(209);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const units = await ackedUnits(owner, chain, ["one", "two"]);
    await dequeue(
      owner,
      units.map((u) => u.unitId),
    );
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN")
        s.reply(m, "RESOURCE_OPENED", {
          resourceId: chain.R,
          heads: [{ seq: 0n, recordId: chain.ids[0] as ControlRecordId }],
          haves: [],
        });
      else if (m.type === "DATA_PUT") s.reply(m, "NACK", { code: 16n });
      return [];
    };
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(server.of("DATA_PUT").map((m) => m.body.objects.length)).toEqual([2, 1, 1]);
    expect(owner.events.filter((e) => e.type === "error" || e.type === "nack")).toEqual([]);
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
  });

  it("re-supplies the unit a server lost before its successor (UNKNOWN_PREVIOUS, §51.1)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(210);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const units = await ackedUnits(owner, chain, ["one", "two", "three"]);
    await dequeue(owner, [units[0]?.unitId as Uint8Array, units[1]?.unitId as Uint8Array]);
    // The server says it holds 1..2, then turns out to have lost 2.
    let stored = 1;
    server.onMessage = (m, s) => {
      const R = chain.R;
      if (m.type === "RESOURCE_OPEN")
        s.reply(m, "RESOURCE_OPENED", {
          resourceId: R,
          heads: [{ seq: 0n, recordId: chain.ids[0] as ControlRecordId }],
          haves: [{ principalId: OWNER.signer.descriptor.principalId, contiguous: 2n }],
        });
      else if (m.type === "DATA_HAVE")
        s.reply(m, "DATA_HAVE", {
          resourceId: R,
          haves: [{ principalId: OWNER.signer.descriptor.principalId, contiguous: BigInt(stored) }],
        });
      else if (m.type === "DATA_PUT") {
        const seqs = m.body.objects.map(
          (o) => units.findIndex((u) => toHex(u.bytes) === toHex(o)) + 1,
        );
        if (seqs[0] !== stored + 1)
          s.reply(m, "NACK", { code: 23n, details: units[stored]?.unitId as Uint8Array });
        else {
          stored = seqs.at(-1) as number;
          s.reply(m, "ACK", {
            requestType: 33n,
            objectIds: m.body.objects.map((o) => hash32(sha(o))),
          });
        }
      }
      return [];
    };
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(300);
    await owner.sync.idle();
    const sent = server
      .of("DATA_PUT")
      .map((m) =>
        m.body.objects.map((o) => units.findIndex((u) => toHex(u.bytes) === toHex(o)) + 1),
      );
    expect(sent).toEqual([[3], [2], [3]]);
    expect(stored).toBe(3);
    expect(
      owner.events
        .filter((e) => e.type === "nack")
        .map((e) => (e as { outcome: { kind: string } }).outcome.kind),
    ).toEqual(["needs-offer"]);
    expect(await owner.storage.outbound.list(chain.R)).toEqual([]);
  });

  it("re-hosts a Resource a route that hosted it lost, and offers it everything (§41.1)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(211);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    const units = await ackedUnits(owner, chain, ["one"]);
    await dequeue(
      owner,
      units.map((u) => u.unitId),
    );
    hostOf(
      server,
      chain,
      units.map((u) => u.bytes),
    );
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    // The server is restored from a copy without the Resource.
    let hosted = false;
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN") {
        if (!hosted) s.reply(m, "NACK", { code: 6n });
        else
          s.reply(m, "RESOURCE_OPENED", {
            resourceId: chain.R,
            heads: [{ seq: 0n, recordId: chain.ids[0] as ControlRecordId }],
            haves: [],
          });
      } else if (m.type === "RESOURCE_HOST") {
        expect(m.body.genesis).toEqual(chain.records[0]);
        hosted = true;
        s.reply(m, "RESOURCE_HOSTED", { resourceId: chain.R, durability: 2n });
      } else if (m.type === "DATA_PUT") s.reply(m, "ACK", { requestType: 33n, objectIds: [] });
      return [];
    };
    server.current.drop();
    await settle(50);
    clock.t += 1000;
    owner.sync.tick(clock.t);
    await settle(300);
    await owner.sync.idle();
    expect(owner.events.filter((e) => e.type === "rehost")).toEqual([
      { type: "rehost", resourceId: chain.R, url: "ws://127.0.0.1:1/v1/ws", outcome: "hosted" },
    ]);
    expect(owner.sync.resourceState(chain.R)).toBe("LIVE");
    expect(server.of("DATA_PUT")[0]?.body.objects).toEqual([units[0]?.bytes]);
    expect(owner.events.some((e) => e.type === "resource-refused")).toBe(false);
  });

  it("stops at a refused re-host: an event and a refusal, no retry (§41.1)", async () => {
    const server = new FakeServer();
    const clock = { t: 0 };
    const chain = chainFor(212);
    const owner = client(OWNER, server, clock);
    await ownerState(owner, chain);
    hostOf(server, chain);
    owner.sync.open(owner.binding(chain.R));
    owner.sync.start();
    await settle(200);
    await owner.sync.idle();
    server.onMessage = (m, s) => {
      if (m.type === "RESOURCE_OPEN") s.reply(m, "NACK", { code: 6n });
      else if (m.type === "RESOURCE_HOST") s.reply(m, "NACK", { code: 20n });
      return [];
    };
    server.current.drop();
    await settle(50);
    clock.t += 1000;
    owner.sync.tick(clock.t);
    await settle(300);
    await owner.sync.idle();
    expect(owner.events.filter((e) => e.type === "rehost")).toEqual([
      {
        type: "rehost",
        resourceId: chain.R,
        url: "ws://127.0.0.1:1/v1/ws",
        outcome: "refused",
        code: "HOSTING_DENIED",
      },
    ]);
    expect(owner.sync.resourceRefusal(chain.R)).toMatchObject({
      code: "HOSTING_DENIED",
      request: "rehost",
    });
    expect(server.of("RESOURCE_HOST")).toHaveLength(1);
    for (let i = 0; i < 3; i++) {
      clock.t += 60_000;
      owner.sync.tick(clock.t);
      await settle(20);
    }
    await owner.sync.idle();
    expect(server.of("RESOURCE_HOST")).toHaveLength(1);
  });
});
