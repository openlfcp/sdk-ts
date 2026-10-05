// Shared pieces of the live interop tests against the Rust reference
// server (LFCP-039a, LFCP-038): parties, a client "side" with storage,
// secrets, a Shared Objects replica, applier, queue and sync session, and
// helpers to create, host and share a Resource. Synthetic keys only.

import {
  createQueuedDataUnit,
  DataUnitApplier,
  dekResolver,
  loadControlChain,
  OutboundQueue,
  ProfileCheckpointer,
  queueControlRecord,
  queueKeyPackage,
  type SnapshotBinding,
  SyncClient,
  type SyncEvent,
  saveControlChain,
  startSyncDriver,
  type WebSocketFactory,
} from "@openlfcp/client";
import {
  type ControlRecordId,
  type DataUnitId,
  dataEpoch,
  type PrincipalId,
  type ResourceId,
} from "@openlfcp/core";
import {
  type AgreementKeyPair,
  dekCommitment,
  exportSecretKeyBytes,
  importAgreementKey,
  importSigningKey,
  type ResourceDEK,
} from "@openlfcp/crypto";
import {
  checkChange,
  type LocalChange,
  PROFILE_ID,
  type SharedObjectsDataProfile,
} from "@openlfcp/shared-objects";
import {
  dekSecretRef,
  type EpochRow,
  InMemoryLfcpStorage,
  InMemorySecretStore,
  type LfcpStorage,
  type SecretStore,
} from "@openlfcp/storage";
import {
  principalDescriptorFromKeys,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
} from "@openlfcp/wire";

declare const setTimeout: (fn: () => void, ms: number) => unknown;
declare const setInterval: (fn: () => void, ms: number) => unknown;
declare const clearInterval: (handle: unknown) => void;

export const bytes32 = (from: number): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);

export interface Party {
  readonly signer: Signer;
  readonly agreement: AgreementKeyPair;
}

export const party = (seed: number): Party => {
  const key = importSigningKey(bytes32(seed));
  const agreement = importAgreementKey(bytes32(seed + 100));
  return { signer: { key, descriptor: principalDescriptorFromKeys(key, agreement) }, agreement };
};

export const sleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(() => r(undefined), ms));

export async function waitFor(
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

export interface SideOptions {
  readonly url: string;
  readonly resource: ResourceId;
  readonly who: Party;
  readonly profile: SharedObjectsDataProfile;
  /** Defaults to in-memory storage and secrets. */
  readonly storage?: LfcpStorage;
  readonly secrets?: SecretStore;
  /** Load offered Snapshots and allow publishing (default true). */
  readonly snapshots?: boolean;
  /** Checkpoint the replica (debounced, every tick). */
  readonly checkpoints?: boolean;
  /** The WebSocket to use (default the platform's): e.g. a tap or a fault injector. */
  readonly webSocket?: WebSocketFactory;
}

/** One client: storage, secrets, replica, applier, queue, sync session and its driver. */
export class Side {
  readonly storage: LfcpStorage;
  readonly secrets: SecretStore;
  readonly outbound: OutboundQueue;
  readonly events: SyncEvent[] = [];
  readonly profile: SharedObjectsDataProfile;
  readonly applier: DataUnitApplier;
  readonly checkpointer: ProfileCheckpointer | undefined;
  readonly client: SyncClient;
  readonly resource: ResourceId;
  readonly who: Party;
  readonly #snapshots: boolean;
  #stopDriver: (() => void) | null = null;

  constructor(o: SideOptions) {
    this.resource = o.resource;
    this.who = o.who;
    this.storage = o.storage ?? new InMemoryLfcpStorage();
    this.secrets = o.secrets ?? new InMemorySecretStore();
    this.outbound = new OutboundQueue({ storage: this.storage });
    this.profile = o.profile;
    this.#snapshots = o.snapshots ?? true;
    const profile = this.profile;
    this.applier = new DataUnitApplier({
      storage: this.storage,
      dek: dekResolver(this.storage, this.secrets, o.resource),
      handlers: [
        {
          dataProfile: profile.dataProfile,
          codecFor: (u) => profile.codecFor(u),
          apply: (u, v) => profile.apply(u, v as never),
          exclude: (ids) => profile.exclude(ids),
          has: (id) => profile.has(id),
          reset: () => profile.reset(),
        },
      ],
    });
    this.checkpointer =
      o.checkpoints === true
        ? new ProfileCheckpointer(this.storage, profile, { minIntervalMs: 0 })
        : undefined;
    this.client = new SyncClient({
      url: o.url,
      signer: o.who.signer,
      agreement: o.who.agreement,
      storage: this.storage,
      secrets: this.secrets,
      outbound: this.outbound,
      now: () => Date.now(),
      reconnect: () => 200,
      antiEntropyMs: 1000,
      ...(o.webSocket === undefined ? {} : { webSocket: o.webSocket }),
    });
    this.client.on((e) => this.events.push(e));
  }

  get me(): PrincipalId {
    return this.who.signer.descriptor.principalId;
  }

  /** Starts the session and its driver, and opens the Resource unless told not to (e.g. before hosting it). */
  start(options: { readonly open?: boolean } = {}): void {
    if (options.open !== false) this.open();
    this.client.start();
    this.#stopDriver ??= startSyncDriver(
      this.client,
      { setInterval, clearInterval, now: () => Date.now() },
      100,
    );
  }

  /** Registers the Resource with the session (opened now, or when READY). */
  open(): void {
    const profile = this.profile;
    const snapshot: SnapshotBinding<Uint8Array> | undefined = this.#snapshots
      ? {
          codec: profile.snapshotCodec(),
          load: (save) => void profile.loadSnapshot(save),
          current: () => profile.snapshotState(),
        }
      : undefined;
    this.client.open({
      resourceId: this.resource,
      applier: this.applier,
      ...(this.checkpointer === undefined ? {} : { checkpointer: this.checkpointer }),
      ...(snapshot === undefined ? {} : { snapshot: snapshot as SnapshotBinding<unknown> }),
    });
  }

  /** Seals a local change as this side's next Data Unit (recorded with the profile) and flushes. */
  async write(local: LocalChange): Promise<DataUnitId> {
    const chain = await loadControlChain(this.storage, this.resource);
    if (chain?.kind !== "linear") throw new Error("no chain");
    const dek = await dekResolver(
      this.storage,
      this.secrets,
      this.resource,
    )(chain.state.epoch.epoch);
    if (dek === undefined) throw new Error("no DEK");
    const profile = this.profile;
    const checkpointer = this.checkpointer;
    const u = await createQueuedDataUnit(
      this.storage,
      {
        view: chain,
        controlHead: chain.state.head,
        actor: this.who.signer,
        dek,
        profile: profile.codecFor({ resourceId: this.resource, actor: this.me }),
        // previous: the SDK's default, the last published unit (§26.2, G-DP1-GAP).
        value: checkChange(local.change),
        onCreated: (created, value) => profile.recordLocal(created.unitId, value),
      },
      () => (checkpointer === undefined ? [] : [checkpointer.write()]),
    );
    this.client.flush();
    return u.unitId;
  }

  async queueEmpty(): Promise<boolean> {
    return (await this.storage.outbound.list(this.resource)).length === 0;
  }

  errors(): SyncEvent[] {
    return this.events.filter((e) => e.type === "error");
  }

  async stop(): Promise<void> {
    this.#stopDriver?.();
    this.#stopDriver = null;
    await this.client.stop();
  }
}

/** A new Resource of `owner` coordinated at `url`: its Genesis, stored with the DEK on `side`. */
export async function createResource(side: Side, url: string, dek: ResourceDEK) {
  const R = side.resource;
  const genesis = signControlRecord(
    { resourceId: R, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: PROFILE_ID,
      owner: side.who.signer.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), dek),
      endpoints: [{ url, priority: 0n }],
      coordinatorUrl: url,
    },
    side.who.signer,
  );
  const chain = validateControlChain([genesis.bytes]);
  if (chain.kind !== "linear") throw new Error(chain.kind);
  const saved = await saveControlChain(side.storage, chain, null);
  if (!saved.ok) throw new Error("the Genesis was not stored");
  await storeDek(side, 0n, dek);
  return genesis;
}

/** Stores a DEK the side holds (secret first, then the epoch's reference). */
export async function storeDek(side: Side, epoch: bigint, dek: ResourceDEK): Promise<void> {
  const ref = dekSecretRef(side.resource, dataEpoch(epoch));
  await side.secrets.put(ref, exportSecretKeyBytes(dek));
  const row = (await side.storage.control.epochs(side.resource)).find(
    (e) => e.epoch === epoch,
  ) as EpochRow;
  await side.storage.commit([
    { op: "put-epoch", resourceId: side.resource, epoch: { ...row, dekRef: ref } },
  ]);
}

/** OWNER grants `who` data/read + data/write on the current head and sends it the epoch-0 DEK. */
export async function grantAndKey(
  owner: Side,
  who: Party,
  dek: ResourceDEK,
): Promise<ControlRecordId> {
  const chain = await loadControlChain(owner.storage, owner.resource);
  if (chain?.kind !== "linear") throw new Error("no chain");
  const grant = signControlRecord(
    {
      resourceId: owner.resource,
      controlSeq: chain.state.seq + 1n,
      prevControlId: chain.state.head,
    },
    {
      type: "CAPABILITY_GRANT",
      subject: who.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    },
    owner.who.signer,
  );
  await queueControlRecord(owner.storage, grant.bytes);
  const kp = await sealKeyPackage({
    resourceId: owner.resource,
    epoch: dataEpoch(0n),
    controlHead: grant.recordId,
    recipient: who.signer.descriptor,
    dek,
    signer: owner.who.signer,
  });
  await queueKeyPackage(owner.storage, kp.bytes);
  owner.client.flush();
  return grant.recordId;
}
