// LFCP-039a: the TypeScript client against the Rust reference server, live.
// The first TS↔Rust interop over a real WebSocket:
//
// 1. OWNER hosts a new Resource (RESOURCE_HOST), opens it, grants BOB
//    (CONTROL_PUT) and sends BOB a Key Package (KEY_PACKAGE_PUT), all
//    through the outbound queue;
// 2. BOB connects, opens the Resource, catches up Control, Keys and Data;
// 3. OWNER creates a Task (DATA_PUT); BOB receives the live push;
// 4. BOB goes offline and edits while OWNER edits too; BOB reconnects and
//    both replicas converge.
//
// Skipped (with the reason) when cargo or the server checkout is missing.

import {
  createQueuedDataUnit,
  DataUnitApplier,
  dekResolver,
  loadControlChain,
  OutboundQueue,
  queueControlRecord,
  queueKeyPackage,
  SyncClient,
  type SyncEvent,
  saveControlChain,
  startSyncDriver,
} from "@openlfcp/client";
import {
  actorSequence,
  type DataUnitId,
  dataEpoch,
  type ObjectId,
  type PrincipalId,
  resourceId,
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
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  InMemorySecretStore,
} from "@openlfcp/storage";
import {
  principalDescriptorFromKeys,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const setTimeout: (fn: () => void, ms: number) => unknown;
declare const setInterval: (fn: () => void, ms: number) => unknown;
declare const clearInterval: (handle: unknown) => void;
declare const console: { warn(...a: unknown[]): void };

const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const party = (seed: number): { signer: Signer; agreement: AgreementKeyPair } => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const OWNER = party(11);
const BOB = party(51);
const R = resourceId(bytes32(170));
const DEK0 = importResourceDEK(bytes32(90));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;

const sleep = (ms: number) => new Promise((r) => setTimeout(() => r(undefined), ms));
async function waitFor(
  what: string,
  cond: () => boolean | Promise<boolean>,
  ms = 15_000,
): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await cond()) return;
    await sleep(25);
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** One client: its storage, secrets, replica, applier, queue and sync session. */
class Side {
  readonly storage = new InMemoryLfcpStorage();
  readonly secrets = new InMemorySecretStore();
  readonly outbound = new OutboundQueue({ storage: this.storage });
  readonly events: SyncEvent[] = [];
  readonly profile: SharedObjectsDataProfile;
  readonly applier: DataUnitApplier;
  readonly client: SyncClient;
  readonly #stopDriver: () => void;

  constructor(
    readonly who: { signer: Signer; agreement: AgreementKeyPair },
    url: string,
    replica: SharedObjectsReplica,
  ) {
    this.profile = new SharedObjectsDataProfile(replica);
    const profile = this.profile;
    this.applier = new DataUnitApplier({
      storage: this.storage,
      dek: dekResolver(this.storage, this.secrets, R),
      handlers: [
        {
          dataProfile: profile.dataProfile,
          codecFor: (u) => profile.codecFor(u),
          apply: (u, v) => profile.apply(u, v as never),
          exclude: (ids) => profile.exclude(ids),
        },
      ],
    });
    this.client = new SyncClient({
      url,
      signer: who.signer,
      agreement: who.agreement,
      storage: this.storage,
      secrets: this.secrets,
      outbound: this.outbound,
      now: () => Date.now(),
      reconnect: () => 200,
      antiEntropyMs: 1000,
    });
    this.client.on((e) => this.events.push(e));
    this.#stopDriver = startSyncDriver(
      this.client,
      { setInterval, clearInterval, now: () => Date.now() },
      100,
    );
  }

  open(): void {
    this.client.open({ resourceId: R, applier: this.applier });
  }

  get me(): PrincipalId {
    return this.who.signer.descriptor.principalId;
  }

  task(): Task | undefined {
    return this.profile.replica.task(TASK)?.task;
  }

  /** Seals a local change as this side's next Data Unit and flushes the queue. */
  async write(local: LocalChange): Promise<void> {
    const chain = await loadControlChain(this.storage, R);
    if (chain?.kind !== "linear") throw new Error("no chain");
    const dek = await dekResolver(this.storage, this.secrets, R)(chain.state.epoch.epoch);
    if (dek === undefined) throw new Error("no DEK");
    const mine = await this.storage.dataUnits.range(
      R,
      this.me,
      actorSequence(1n),
      actorSequence(2n ** 64n - 1n),
    );
    const previous = mine.filter((u) => u.accepted).at(-1)?.unitId ?? null;
    await createQueuedDataUnit(this.storage, {
      view: chain,
      controlHead: chain.state.head,
      actor: this.who.signer,
      dek,
      profile: this.profile.codecFor({ resourceId: R, actor: this.me }),
      previousUnitId: previous as DataUnitId | null,
      value: checkChange(local.change),
    });
    this.client.flush();
  }

  async queueEmpty(): Promise<boolean> {
    return (await this.storage.outbound.list(R)).length === 0;
  }

  async stop(): Promise<void> {
    this.#stopDriver();
    await this.client.stop();
  }
}

let server: RunningRustServer | undefined;
let skip: string | undefined;

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
});

describe("SyncClient ↔ Rust reference server (live)", () => {
  it("hosts, grants, catches up, pushes live, and converges after an offline edit", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: TS↔Rust interop (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    try {
      // OWNER: a new Resource with the Shared Objects profile, coordinated by this server.
      const genesis = signControlRecord(
        { resourceId: R, controlSeq: 0n, prevControlId: null },
        {
          type: "GENESIS",
          dataProfile: PROFILE_ID,
          owner: OWNER.signer.descriptor,
          dekCommitment: dekCommitment(R, dataEpoch(0n), DEK0),
          endpoints: [{ url, priority: 0n }],
          coordinatorUrl: url,
        },
        OWNER.signer,
      );
      const { replica: ownerReplica, change: init } = SharedObjectsReplica.create({
        resource: R,
        principal: OWNER.signer.descriptor.principalId,
      });
      const owner = new Side(OWNER, url, ownerReplica);
      const chain0 = validateControlChain([genesis.bytes]);
      if (chain0.kind !== "linear") throw new Error(chain0.kind);
      expect(await saveControlChain(owner.storage, chain0, null)).toEqual({ ok: true });
      await owner.secrets.put(dekSecretRef(R, dataEpoch(0n)), exportSecretKeyBytes(DEK0));
      const epoch0 = (await owner.storage.control.epochs(R))[0] as EpochRow;
      await owner.storage.commit([
        {
          op: "put-epoch",
          resourceId: R,
          epoch: { ...epoch0, dekRef: dekSecretRef(R, dataEpoch(0n)) },
        },
      ]);
      await owner.write(init);

      owner.client.start();
      await waitFor("OWNER READY", () => owner.client.connectionState === "READY");
      expect(await owner.client.host(genesis.bytes)).toBe(2n);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
      await waitFor("OWNER init sent", () => owner.queueEmpty());

      // Grant BOB data/read + data/write, and send BOB the epoch-0 DEK.
      const grant = signControlRecord(
        { resourceId: R, controlSeq: 1n, prevControlId: genesis.recordId },
        {
          type: "CAPABILITY_GRANT",
          subject: BOB.signer.descriptor,
          abilities: [1n, 2n],
          delegable: [],
        },
        OWNER.signer,
      );
      await queueControlRecord(owner.storage, grant.bytes);
      const kp = await sealKeyPackage({
        resourceId: R,
        epoch: dataEpoch(0n),
        controlHead: grant.recordId,
        recipient: BOB.signer.descriptor,
        dek: DEK0,
        signer: OWNER.signer,
      });
      await queueKeyPackage(owner.storage, kp.bytes);
      owner.client.flush();
      await waitFor("grant and Key Package ACKed", () => owner.queueEmpty());
      await waitFor(
        "OWNER holds the grant",
        async () =>
          (await loadControlChain(owner.storage, R))?.kind === "linear" &&
          (await owner.storage.control.head(R))?.controlSeq === 1n,
      );

      // BOB connects and catches up.
      const bob = new Side(
        BOB,
        url,
        SharedObjectsReplica.empty({ resource: R, principal: BOB.signer.descriptor.principalId }),
      );
      bob.open();
      bob.client.start();
      await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE");
      expect((await bob.storage.control.head(R))?.controlSeq).toBe(1n);
      expect(bob.profile.replica.root()).toEqual(owner.profile.replica.root());

      // OWNER creates a Task; BOB gets the live push.
      await owner.write(
        owner.profile.replica.apply(
          createTask({
            id: TASK,
            title: "Prepare API contract",
            createdBy: OWNER.signer.descriptor.principalId,
          }).intent,
        ) as LocalChange,
      );
      await waitFor("BOB has the Task", () => bob.task()?.title === "Prepare API contract");

      // BOB offline: both edit; BOB reconnects; both converge.
      await bob.client.stop();
      await bob.write(
        bob.profile.replica.apply(
          setTitle(bob.task() as Task, "Final API contract").intent,
        ) as LocalChange,
      );
      await owner.write(
        owner.profile.replica.apply(
          setStatus(owner.task() as Task, "in_progress").intent,
        ) as LocalChange,
      );
      await waitFor("OWNER edit ACKed", () => owner.queueEmpty());
      bob.client.start();
      await waitFor("BOB edit ACKed", () => bob.queueEmpty());
      await waitFor("convergence", () => {
        const [a, b] = [owner.task(), bob.task()];
        return (
          a?.title === "Final API contract" &&
          b?.status === "in_progress" &&
          JSON.stringify(owner.profile.replica.root()) ===
            JSON.stringify(bob.profile.replica.root())
        );
      });
      expect(owner.events.filter((e) => e.type === "error")).toEqual([]);
      expect(bob.events.filter((e) => e.type === "error")).toEqual([]);
      await owner.stop();
      await bob.stop();
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    }
  }, 120_000);
});
