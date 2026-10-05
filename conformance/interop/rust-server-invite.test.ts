// LFCP-053: link invitations and the one-time claim through the TypeScript
// client against the Rust reference server, live (LFCP-WIRE-01 §18, §18.1,
// §18.2, §25.2, §73):
//
// 1. OWNER hosts a Shared Objects Resource and creates an invitation: a
//    grant to a fresh Invitation Principal (claim_limit 1) and a Key
//    Package sealed to it, through the outbound queue; the bearer link is
//    handed over in memory.
// 2. BOB, a fresh Principal with no grant, accepts it: as the Invitation
//    Principal he fetches the chain, verifies the secret against the grant,
//    opens the invitation's package and claims; then he opens the Resource
//    as himself, gets OWNER's Task, edits it, and OWNER sees the edit.
// 3. CAROL tries the same one-time link and is refused (AUTHORIZATION_FAILED).
// 4. On a second one-time invitation DAVE's claim is held until ERIN's
//    commits: DAVE gets CONTROL_HEAD_MISMATCH, refreshes, and is refused;
//    and two claims racing freely on a third leave exactly one winner.
//
// Skipped (with the reason) when cargo or the server checkout is missing.

import {
  acceptInvitation,
  createInvitation,
  createQueuedDataUnit,
  DataUnitApplier,
  dekResolver,
  type InvitationLink,
  loadControlChain,
  OutboundQueue,
  platformWebSocket,
  SyncClient,
  type SyncEvent,
  saveControlChain,
  startSyncDriver,
  type WebSocketFactory,
  type WebSocketLike,
} from "@openlfcp/client";
import {
  actorSequence,
  type DataUnitId,
  dataEpoch,
  type ObjectId,
  type PrincipalId,
  resourceId,
  toBase64url,
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
  checkChange,
  createTask,
  type LocalChange,
  PROFILE_ID,
  SharedObjectsDataProfile,
  SharedObjectsReplica,
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
  ABILITY,
  decodeEnvelope,
  hasAbility,
  MESSAGE_TYPE,
  parseInviteUri,
  principalDescriptorFromKeys,
  type Signer,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

declare const setTimeout: (fn: () => void, ms: number) => unknown;
declare const setInterval: (fn: () => void, ms: number) => unknown;
declare const clearInterval: (handle: unknown) => void;
declare const console: { warn(...a: unknown[]): void };

type Party = { signer: Signer; agreement: AgreementKeyPair };
const bytes32 = (from: number) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const party = (seed: number): Party => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};
const OWNER = party(12);
const BOB = party(52);
const CAROL = party(72);
const DAVE = party(92);
const ERIN = party(112);
const FRANK = party(132);
const GRACE = party(152);
const HANK = party(172);
const R = resourceId(bytes32(171));
const DEK0 = importResourceDEK(bytes32(91));
const TASK = "017f22e2-79b0-7cc3-98c4-dc0c0c0739a0" as ObjectId;

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

/** One client: storage, secrets, replica, applier, queue and sync session (as in the LFCP-039a test). */
class Side {
  readonly storage: InMemoryLfcpStorage;
  readonly secrets: InMemorySecretStore;
  readonly outbound: OutboundQueue;
  readonly events: SyncEvent[] = [];
  readonly profile: SharedObjectsDataProfile;
  readonly applier: DataUnitApplier;
  readonly client: SyncClient;
  readonly #stopDriver: () => void;

  constructor(
    readonly who: Party,
    url: string,
    replica: SharedObjectsReplica,
    stores?: { storage: InMemoryLfcpStorage; secrets: InMemorySecretStore },
  ) {
    this.storage = stores?.storage ?? new InMemoryLfcpStorage();
    this.secrets = stores?.secrets ?? new InMemorySecretStore();
    this.outbound = new OutboundQueue({ storage: this.storage });
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

  /** A side with an empty replica, on the given (e.g. just joined) storage. */
  static fresh(
    who: Party,
    url: string,
    stores?: { storage: InMemoryLfcpStorage; secrets: InMemorySecretStore },
  ): Side {
    return new Side(
      who,
      url,
      SharedObjectsReplica.empty({ resource: R, principal: who.signer.descriptor.principalId }),
      stores,
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
    await createQueuedDataUnit(this.storage, {
      view: chain,
      controlHead: chain.state.head,
      actor: this.who.signer,
      dek,
      profile: this.profile.codecFor({ resourceId: R, actor: this.me }),
      previousUnitId: (mine.filter((u) => u.accepted).at(-1)?.unitId ?? null) as DataUnitId | null,
      value: checkChange(local.change),
    });
    this.client.flush();
  }

  async queueEmpty(): Promise<boolean> {
    return (await this.storage.outbound.list(R)).length === 0;
  }

  async seq(): Promise<bigint | undefined> {
    return (await this.storage.control.head(R))?.controlSeq;
  }

  async stop(): Promise<void> {
    this.#stopDriver();
    await this.client.stop();
  }
}

/** A joiner's storage and secrets, and the options acceptInvitation needs. */
const joiner = (
  who: Party,
  link: InvitationLink,
  webSocket?: WebSocketFactory,
  abilities?: readonly bigint[],
) => {
  const storage = new InMemoryLfcpStorage();
  const secrets = new InMemorySecretStore();
  return {
    storage,
    secrets,
    accept: () =>
      acceptInvitation({
        link,
        claimant: who,
        storage,
        secrets,
        now: () => Date.now(),
        timeout: sleep(20_000),
        ...(webSocket === undefined ? {} : { webSocket }),
        ...(abilities === undefined ? {} : { abilities }),
      }),
  };
};

/**
 * A WebSocket whose CONTROL_PUT waits for `gate` (a held claim, to lose the
 * race deterministically); `held` is called when the claim is held.
 */
const holdingControlPut =
  (gate: Promise<unknown>, held: () => void): WebSocketFactory =>
  (url, protocols) => {
    const ws = platformWebSocket()(url, protocols);
    return new Proxy(ws, {
      get(target, p) {
        if (p === "send")
          return (data: Uint8Array) => {
            if (decodeEnvelope(data).code === MESSAGE_TYPE.CONTROL_PUT) {
              held();
              void gate.then(() => target.send(data));
            } else target.send(data);
          };
        const v = Reflect.get(target, p);
        return typeof v === "function" ? v.bind(target) : v;
      },
      set(target, p, v) {
        return Reflect.set(target, p, v);
      },
    }) as WebSocketLike;
  };

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

describe("invitations ↔ Rust reference server (live, LFCP-053)", () => {
  it("invites, claims once, syncs and edits as the claimant; refuses every other claim", async (ctx) => {
    if (server === undefined) {
      console.warn(`SKIPPED: TS↔Rust invitations (${skip})`);
      ctx.skip();
      return;
    }
    const url = server.url;
    const sides: Side[] = [];
    try {
      // OWNER hosts the Resource.
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
      const { replica, change: init } = SharedObjectsReplica.create({
        resource: R,
        principal: OWNER.signer.descriptor.principalId,
      });
      const owner = new Side(OWNER, url, replica);
      sides.push(owner);
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
      await owner.client.host(genesis.bytes);
      owner.open();
      await waitFor("OWNER LIVE", () => owner.client.resourceState(R) === "LIVE");
      await owner.write(
        owner.profile.replica.apply(
          createTask({
            id: TASK,
            title: "Prepare API contract",
            createdBy: OWNER.signer.descriptor.principalId,
          }).intent,
        ) as LocalChange,
      );
      await waitFor("OWNER units sent", () => owner.queueEmpty());

      // 1. OWNER invites: grant + Key Package to a fresh Invitation Principal, queued.
      const invite = async () => {
        const created = await createInvitation({
          storage: owner.storage,
          resourceId: R,
          inviter: OWNER.signer,
          dek: DEK0,
          endpoints: [url],
        });
        const seq = await owner.seq();
        owner.client.flush();
        await waitFor("invitation ACKed", () => owner.queueEmpty());
        await waitFor(
          "OWNER holds the grant",
          async () => (await owner.seq()) === (seq ?? 0n) + 1n,
        );
        return created;
      };
      const first = await invite();
      // The link is a key: it never prints, and its parts are what was created.
      expect(JSON.stringify({ link: first.link })).toBe('{"link":"[redacted]"}');
      expect(String(first.link)).toBe("[redacted]");
      const parsed = parseInviteUri(first.link.reveal());
      expect(toBase64url(parsed.grantId)).toBe(toBase64url(first.grantId));
      expect(parsed.endpoints).toEqual([url]);
      const ownerChain = await loadControlChain(owner.storage, R);
      if (ownerChain?.kind !== "linear") throw new Error("no owner chain");
      const grant = ownerChain.state.grants.get(toHex(first.grantId));
      expect(toHex(grant?.subject ?? new Uint8Array())).toBe(
        toHex(first.invitationPrincipal.principalId),
      );
      expect(grant?.claimLimit).toBe(1n);
      expect(grant?.abilities).toEqual([
        ABILITY.DATA_READ,
        ABILITY.DATA_WRITE,
        ABILITY.INVITE_CLAIM,
      ]);

      // 2. BOB (no grant) accepts: verify, open the invitation package, claim.
      const bobJoin = joiner(BOB, first.link);
      const bobResult = await bobJoin.accept();
      expect(bobResult).toMatchObject({
        kind: "claimed",
        abilities: [ABILITY.DATA_READ, ABILITY.DATA_WRITE],
        attempts: ["ACK"],
      });
      const bobChain = await loadControlChain(bobJoin.storage, R);
      if (bobChain?.kind !== "linear") throw new Error("no BOB chain");
      expect(
        hasAbility(bobChain.state, BOB.signer.descriptor.principalId, ABILITY.DATA_WRITE),
      ).toBe(true);
      expect(
        hasAbility(bobChain.state, BOB.signer.descriptor.principalId, ABILITY.INVITE_CLAIM),
      ).toBe(false);

      // BOB opens as himself on the joined storage: no Key Package to BOB is needed (§73).
      const bob = Side.fresh(BOB, url, bobJoin);
      sides.push(bob);
      bob.open();
      bob.client.start();
      await waitFor("BOB LIVE", () => bob.client.resourceState(R) === "LIVE");
      await waitFor("BOB has OWNER's Task", () => bob.task()?.title === "Prepare API contract");
      await bob.write(
        bob.profile.replica.apply(
          setTitle(bob.task() as Task, "Agreed API contract").intent,
        ) as LocalChange,
      );
      await waitFor("BOB's edit ACKed", () => bob.queueEmpty());
      await waitFor("OWNER sees BOB's edit", () => owner.task()?.title === "Agreed API contract");
      expect(bob.events.filter((e) => e.type === "error")).toEqual([]);
      expect(bob.events.some((e) => e.type === "key-blocked")).toBe(false);

      // 3. CAROL tries the same one-time link: the coordinator refuses the claim.
      const carol = joiner(CAROL, first.link);
      expect(await carol.accept()).toMatchObject({
        kind: "refused",
        code: "AUTHORIZATION_FAILED",
        attempts: ["AUTHORIZATION_FAILED"],
      });
      expect(await carol.storage.control.head(R)).toBeUndefined();

      // 4a. A lost race, deterministically: DAVE's CONTROL_PUT waits for ERIN's claim.
      await waitFor("OWNER sees BOB's claim", async () => (await owner.seq()) === 2n);
      const second = await invite();
      // Escalation: abilities outside the grant, or invite/claim itself (not delegable),
      // are refused by the coordinator and consume nothing (§18.1 rule 4).
      for (const abilities of [
        [ABILITY.DATA_READ, ABILITY.KEY_DISTRIBUTE],
        [ABILITY.DATA_READ, ABILITY.INVITE_CLAIM],
      ])
        expect(await joiner(HANK, second.link, undefined, abilities).accept()).toMatchObject({
          kind: "refused",
          code: "AUTHORIZATION_FAILED",
        });

      let erinDone: (v: unknown) => void = () => undefined;
      const erinClaimed = new Promise((r) => {
        erinDone = r;
      });
      let daveHeld: (v: unknown) => void = () => undefined;
      const daveClaimHeld = new Promise((r) => {
        daveHeld = r;
      });
      const dave = joiner(
        DAVE,
        second.link,
        holdingControlPut(erinClaimed, () => daveHeld(true)),
      );
      const erin = joiner(ERIN, second.link);
      const daveResult = dave.accept();
      // DAVE has fetched the chain and built his claim on it before ERIN claims.
      await daveClaimHeld;
      const erinResult = await erin.accept();
      erinDone(undefined);
      expect(erinResult).toMatchObject({ kind: "claimed", attempts: ["ACK"] });
      expect(await daveResult).toMatchObject({
        kind: "refused",
        code: "AUTHORIZATION_FAILED",
        attempts: ["CONTROL_HEAD_MISMATCH", "AUTHORIZATION_FAILED"],
      });

      // 4b. Two claims racing freely on a third invitation: exactly one wins.
      await waitFor("OWNER sees ERIN's claim", async () => (await owner.seq()) === 4n);
      const third = await invite();
      const results = await Promise.all([
        joiner(FRANK, third.link).accept(),
        joiner(GRACE, third.link).accept(),
      ]);
      expect(results.map((r) => r.kind).sort()).toEqual(["claimed", "refused"]);
      expect(results.find((r) => r.kind === "refused")).toMatchObject({
        code: "AUTHORIZATION_FAILED",
      });

      // OWNER's chain shows every grant and claim, and three claimants hold grants.
      await waitFor("OWNER sees the claims", async () => (await owner.seq()) === 6n);
      const final = await loadControlChain(owner.storage, R);
      if (final?.kind !== "linear") throw new Error("no final chain");
      const winners = [BOB, ERIN, FRANK, GRACE, CAROL, DAVE].filter((p) =>
        hasAbility(final.state, p.signer.descriptor.principalId, ABILITY.DATA_READ),
      );
      expect(winners).toHaveLength(3);

      // The secrets never reach the server's log.
      const log = server.log();
      for (const link of [first.link, second.link, third.link]) {
        const uri = link.reveal();
        expect(log).not.toContain(uri);
        expect(log).not.toContain(uri.slice(uri.indexOf("#secret=") + 8));
      }
      expect(owner.events.filter((e) => e.type === "error")).toEqual([]);
    } catch (e) {
      throw new Error(
        `${e instanceof Error ? e.message : String(e)}\n--- server log (tail) ---\n${server.log().slice(-4000)}`,
      );
    } finally {
      for (const s of sides) await s.stop();
    }
  }, 180_000);
});
