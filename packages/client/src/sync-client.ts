import {
  actorSequence,
  type ControlRecordId,
  type DataEpoch,
  type DataUnitId,
  dataEpoch,
  type Hash32,
  LfcpError,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { type AgreementKeyPair, exportSecretKeyBytes } from "@openlfcp/crypto";
import { dekSecretRef, type EpochRow, type LfcpStorage, type SecretStore } from "@openlfcp/storage";
import {
  type ActorRange,
  type AnyMessage,
  addSequence,
  batchDataRanges,
  type ChainResult,
  type ClientConnectionState,
  type ControlHeadRef,
  canonicalFrontierToCbor,
  createMessage,
  type DataProfileCodec,
  type HaveVector,
  hasSequence,
  type LfcpMessage,
  type LiveActorHave,
  localControlOf,
  MESSAGE_TYPE,
  missingFrom,
  normalizeLiveHaves,
  parseControlRecord,
  parseDataUnit,
  planControlSync,
  type ReadySession,
  receiveKeyPackage,
  receiveSnapshot,
  type Signer,
  type SnapshotSummary,
  validateControlChain,
} from "@openlfcp/wire";
import { encode } from "@openlfcp/wire/cbor";
import type { ApplyOutcome, DataUnitApplier, EpochReconciliation } from "./apply.js";
import type { ProfileCheckpointer } from "./checkpoint.js";
import { LfcpConnection, type WebSocketFactory } from "./connection.js";
import type { AckOutcome, NackOutcome, OutboundQueue, StaleOutboundUnit } from "./outbound.js";
import { resourceSyncState, snapshotFrontier } from "./outbound.js";
import { createQueuedSnapshot } from "./queue.js";
import {
  type ResourcePhase,
  type ResourcePhaseEvent,
  resourcePhaseTransition,
} from "./resource-state.js";
import { dekResolver, loadControlChain, saveControlChain, saveControlConflict } from "./storage.js";

/**
 * The client sync session (LFCP-039a): one LFCP connection to a server and
 * the §65 machine of every Resource opened on it, orchestrating the parts
 * built before it. It adds no protocol rule of its own:
 *
 * - connection, handshake, heartbeat, size limits: LfcpConnection;
 * - Control catch-up: planControlSync, then validateControlChain over the
 *   stored records and the fetched ones; a fork is stored and surfaced
 *   (CONTROL_CONFLICT), never resolved;
 * - keys: KEY_PACKAGE_GET for epochs without a DEK, receiveKeyPackage, the
 *   DEK into the SecretStore before its reference into storage;
 * - data: Have Vectors (missingFrom, ≤256 ranges per DATA_GET), every unit
 *   through the DataUnitApplier; periodic DATA_HAVE (§69: anti-entropy);
 * - outbound: OutboundQueue, flushed once keys are in place (§88 step 6),
 *   ACK and NACK routed back to it;
 * - on every newly validated Control state: DataUnitApplier.reconcileEpochs
 *   AND OutboundQueue.reconcileEpochs (G-EP7, §88 step 7).
 *
 * Time and timers belong to the caller: tick(now) does the periodic work
 * (heartbeat, anti-entropy, retries, checkpoints, reconnect), and a thin
 * driver may call it from a timer (startSyncDriver). Events tell the
 * application what happened; nothing is logged, plaintext never.
 */

/** A Resource to synchronize: its Data Profile applier (and optional checkpoints). */
/**
 * How a Data Profile reads and writes Snapshots (§29, §66 step 3): its §13
 * codec, loading a received Snapshot's state, and the state to publish
 * (for Shared Objects: snapshotCodec(), loadSnapshot(), snapshotState()).
 */
export interface SnapshotBinding<T> {
  readonly codec: DataProfileCodec<T>;
  load(value: T): void;
  current(): T;
}

/** A Resource to synchronize: its Data Profile applier (and optional checkpoints and Snapshots). */
export interface ResourceBinding {
  readonly resourceId: ResourceId;
  readonly applier: DataUnitApplier;
  readonly checkpointer?: ProfileCheckpointer;
  /** Load an offered Snapshot instead of replaying every unit, and allow publishing. */
  readonly snapshot?: SnapshotBinding<unknown>;
}

/** When to try connecting again after the `attempt`-th failure (1, 2, …): a delay in ms, or null to stop. */
export type ReconnectPolicy = (attempt: number) => number | null;

/** 1 s, doubling, at most 60 s, forever. */
export const defaultReconnect: ReconnectPolicy = (attempt) =>
  Math.min(60_000, 1000 * 2 ** (attempt - 1));

export interface SyncClientOptions {
  readonly url: string;
  /** The session and writing Principal. */
  readonly signer: Signer;
  /** Its X25519 key pair, to open Key Packages addressed to it. */
  readonly agreement: AgreementKeyPair;
  readonly storage: LfcpStorage;
  readonly secrets: SecretStore;
  readonly outbound: OutboundQueue;
  /** The caller's clock, in milliseconds. */
  readonly now: () => number;
  readonly webSocket?: WebSocketFactory;
  readonly reconnect?: ReconnectPolicy;
  /** How often a LIVE Resource exchanges DATA_HAVE (§69); default 30 s. */
  readonly antiEntropyMs?: number;
  /** An opaque hosting credential for AUTH (§36): server policy only. */
  readonly credential?: Uint8Array;
  readonly dataProfiles?: readonly string[];
  /**
   * Whether to publish a Snapshot of a LIVE Resource now, asked on every
   * tick with the number of units merged since the last one; no automatic
   * schedule otherwise (publishSnapshot can also be called directly).
   */
  readonly snapshotPolicy?: (resourceId: ResourceId, unitsSinceLast: number) => boolean;
}

/** What the session reports to the application. */
export type SyncEvent =
  | { readonly type: "connection"; readonly state: ClientConnectionState; readonly reason?: string }
  | {
      readonly type: "resource-state";
      readonly resourceId: ResourceId;
      readonly state: ResourcePhase;
    }
  /** A received unit's outcome (merged, held, quarantined, equivocation, …). */
  | { readonly type: "unit"; readonly resourceId: ResourceId; readonly outcome: ApplyOutcome }
  /** Merged units a new Key Epoch excluded, and the objects that changed (G-EP7). */
  | {
      readonly type: "epoch-reconciled";
      readonly resourceId: ResourceId;
      readonly applied: EpochReconciliation;
      readonly outbound: readonly StaleOutboundUnit[];
    }
  | {
      readonly type: "control-conflict";
      readonly resourceId: ResourceId;
      readonly heads: readonly ControlRecordId[];
    }
  | {
      readonly type: "key-blocked";
      readonly resourceId: ResourceId;
      readonly epochs: readonly DataEpoch[];
    }
  /** A Snapshot was loaded (§66 step 3); only units beyond its frontier are fetched. */
  | {
      readonly type: "snapshot-loaded";
      readonly resourceId: ResourceId;
      readonly snapshotId: Hash32;
      readonly frontier: HaveVector;
    }
  | {
      readonly type: "snapshot-published";
      readonly resourceId: ResourceId;
      readonly snapshotId: Hash32;
    }
  /** Stored accepted units applied again to a profile state that lacked them (restart). */
  | {
      readonly type: "replayed";
      readonly resourceId: ResourceId;
      readonly replayed: readonly DataUnitId[];
      readonly skipped: readonly { readonly unitId: DataUnitId; readonly reason: string }[];
    }
  | { readonly type: "ack"; readonly outcome: AckOutcome }
  /** A NACK of an outbound object: stale, equivocation alarm, rejected, repropose, … */
  | { readonly type: "nack"; readonly outcome: NackOutcome }
  /** A refusal or failure that concerns a Resource or the session (codes and reasons, never payloads). */
  | {
      readonly type: "error";
      readonly resourceId?: ResourceId;
      readonly code: string;
      readonly message: string;
    };

type Request =
  | { readonly kind: "open"; readonly resource: string }
  | { readonly kind: "close"; readonly resource: string }
  | { readonly kind: "control"; readonly resource: string }
  | { readonly kind: "keys"; readonly resource: string }
  | { readonly kind: "data-get"; readonly resource: string }
  | { readonly kind: "data-have"; readonly resource: string }
  | { readonly kind: "snapshot"; readonly resource: string }
  | {
      readonly kind: "host";
      readonly resolve: (durability: bigint) => void;
      readonly reject: (error: Error) => void;
    };

interface ResourceContext {
  readonly binding: ResourceBinding;
  state: ResourcePhase;
  /** The application wants it open (reopened after a reconnect). */
  wanted: boolean;
  /** The validated linear chain, once Control sync completed. */
  view: Extract<ChainResult, { kind: "linear" }> | null;
  /** Records fetched in the current Control round. */
  fetched: Uint8Array[];
  /** The Control sequence the current round must reach. */
  controlTarget: bigint | null;
  /** What the server holds, from RESOURCE_OPENED or its DATA_HAVE. */
  remoteHave: HaveVector;
  /** The sequences requested in this data round, and those received. */
  expected: HaveVector;
  received: HaveVector;
  /** Units pushed before the keys and chain were ready, applied in DATA_SYNC. */
  early: Uint8Array[];
  lastHave: number;
  lastKeyRequest: number;
  missingEpochs: DataEpoch[];
  /** The newest Snapshot the server offered in RESOURCE_OPENED. */
  offered: SnapshotSummary | null;
  /** A SNAPSHOT_GET is outstanding: units wait in `early`. */
  snapshotPending: boolean;
  /** Units inside a stored Snapshot's frontier: accepted as covered, not merged again. */
  covered: HaveVector;
  unitsSinceSnapshot: number;
  /** The ranges the last data round requested (to detect a round without progress). */
  lastRound: string;
}

const SUBSCRIBE_DATA_AND_CONTROL = 0b11n;
const iso = (ms: number): string => new Date(ms).toISOString();
const haveToLive = (vector: HaveVector): LiveActorHave[] =>
  vector.map((h) => ({
    principalId: h.principalId,
    contiguous: h.contiguous,
    ...(h.extras.length > 0 ? { ranges: h.extras } : {}),
  }));

export class SyncClient {
  readonly #o: SyncClientOptions;
  readonly #connection: LfcpConnection;
  readonly #resources = new Map<string, ResourceContext>();
  readonly #requests = new Map<string, Request>();
  readonly #listeners = new Set<(event: SyncEvent) => void>();
  readonly #antiEntropyMs: number;
  #stopped = true;
  #attempt = 0;
  #reconnectAt: number | null = null;
  /** Serializes message handling: each message is handled after the previous one finished. */
  #queue: Promise<void> = Promise.resolve();

  constructor(options: SyncClientOptions) {
    this.#o = options;
    this.#antiEntropyMs = options.antiEntropyMs ?? 30_000;
    this.#connection = new LfcpConnection(
      {
        url: options.url,
        signer: options.signer,
        now: options.now,
        ...(options.webSocket === undefined ? {} : { webSocket: options.webSocket }),
        ...(options.credential === undefined ? {} : { credential: options.credential }),
        ...(options.dataProfiles === undefined ? {} : { dataProfiles: options.dataProfiles }),
      },
      {
        state: (state) => this.#emit({ type: "connection", state }),
        ready: (ready) => this.#serial(() => this.#onReady(ready)),
        message: (m) => this.#serial(() => this.#onMessage(m)),
        closed: (reason) => this.#serial(() => this.#onClosed(reason)),
      },
    );
  }

  /** Subscribes to session events; returns the unsubscribe function. */
  on(listener: (event: SyncEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #emit(event: SyncEvent): void {
    for (const l of this.#listeners) l(event);
  }

  #serial(fn: () => Promise<void> | void): void {
    this.#queue = this.#queue.then(fn).catch((e: unknown) =>
      this.#emit({
        type: "error",
        code: "INTERNAL",
        message: e instanceof Error ? e.message : String(e),
      }),
    );
  }

  /** Resolves once every message received so far has been handled (tests and shutdown). */
  idle(): Promise<void> {
    return this.#queue;
  }

  get connectionState(): ClientConnectionState {
    return this.#connection.state;
  }

  resourceState(resource: ResourceId): ResourcePhase {
    return this.#resources.get(toHex(resource))?.state ?? "CLOSED";
  }

  /** Connects, and reconnects after losses (per the ReconnectPolicy) until stop(). */
  start(): void {
    this.#stopped = false;
    this.#reconnectAt = null;
    this.#connection.connect();
  }

  /** Closes the connection and stops reconnecting. Local state stays usable. */
  async stop(): Promise<void> {
    this.#stopped = true;
    this.#reconnectAt = null;
    this.#connection.close("stopped by the application");
    await this.idle();
  }

  /** Registers a Resource and opens it now (or when the session is READY). */
  open(binding: ResourceBinding): void {
    const key = toHex(binding.resourceId);
    let ctx = this.#resources.get(key);
    if (ctx === undefined) {
      ctx = {
        binding,
        state: "CLOSED",
        wanted: true,
        view: null,
        fetched: [],
        controlTarget: null,
        remoteHave: [],
        expected: [],
        received: [],
        early: [],
        lastHave: 0,
        lastKeyRequest: 0,
        missingEpochs: [],
        offered: null,
        snapshotPending: false,
        covered: [],
        unitsSinceSnapshot: 0,
        lastRound: "",
      };
      this.#resources.set(key, ctx);
    }
    ctx.wanted = true;
    if (this.#connection.state === "READY")
      this.#serial(() => this.#sendOpen(ctx as ResourceContext));
  }

  /** RESOURCE_CLOSE (§43): no more pushes; local state stays usable. */
  close(resource: ResourceId): void {
    const ctx = this.#resources.get(toHex(resource));
    if (ctx === undefined) return;
    ctx.wanted = false;
    if (ctx.state !== "CLOSED" && this.#connection.state === "READY") {
      this.#request(
        { kind: "close", resource: toHex(resource) },
        createMessage("RESOURCE_CLOSE", { resourceId: resource }),
      );
    }
    this.#move(ctx, "CLOSE");
  }

  /** RESOURCE_HOST (§39): asks the server to host a Resource from its exact Genesis bytes; resolves with the durability applied. */
  host(genesis: Uint8Array, credential?: Uint8Array): Promise<bigint> {
    return new Promise((resolve, reject) => {
      try {
        this.#request(
          { kind: "host", resolve, reject },
          createMessage("RESOURCE_HOST", {
            genesis,
            ...(credential === undefined ? {} : { credential }),
          }),
        );
      } catch (e) {
        reject(e as Error);
      }
    });
  }

  /** Sends what the outbound queue has due for every Resource past KEY_SYNC (e.g. after a local write). */
  flush(): void {
    this.#serial(async () => {
      for (const ctx of this.#resources.values()) await this.#flush(ctx);
    });
  }

  /**
   * The periodic work, on the caller's clock: heartbeat (§38), reconnect,
   * anti-entropy DATA_HAVE for LIVE Resources (§69), Key Package retries,
   * due outbound retries and debounced checkpoints.
   */
  tick(now: number): void {
    if (this.#connection.state === "DISCONNECTED") {
      if (!this.#stopped && this.#reconnectAt !== null && now >= this.#reconnectAt) {
        this.#reconnectAt = null;
        this.#connection.connect();
      }
      return;
    }
    if (!this.#connection.tick(now)) return;
    this.#serial(async () => {
      for (const ctx of this.#resources.values()) {
        if (ctx.state === "LIVE" && now - ctx.lastHave >= this.#antiEntropyMs)
          this.#sendHave(ctx, now);
        if (ctx.state === "KEY_BLOCKED" && now - ctx.lastKeyRequest >= this.#antiEntropyMs)
          this.#requestKeys(ctx, now);
        await this.#flush(ctx);
        await ctx.binding.checkpointer?.maybeFlush(now);
        if (
          ctx.state === "LIVE" &&
          ctx.binding.snapshot !== undefined &&
          this.#o.snapshotPolicy?.(ctx.binding.resourceId, ctx.unitsSinceSnapshot) === true
        )
          await this.#publish(ctx);
      }
    });
  }

  // -------------------------------------------------------------------------
  // plumbing

  #request(request: Request, message: LfcpMessage): void {
    this.#requests.set(toHex(message.messageId), request);
    this.#connection.send(message);
  }

  #move(ctx: ResourceContext, event: ResourcePhaseEvent): boolean {
    const next = resourcePhaseTransition(ctx.state, event);
    if (next === undefined) return false;
    ctx.state = next;
    this.#emit({ type: "resource-state", resourceId: ctx.binding.resourceId, state: next });
    return true;
  }

  #ctx(resource: Uint8Array): ResourceContext | undefined {
    return this.#resources.get(toHex(resource));
  }

  #error(code: string, message: string, resourceId?: ResourceId): void {
    this.#emit({
      type: "error",
      code,
      message,
      ...(resourceId === undefined ? {} : { resourceId }),
    });
  }

  async #onReady(ready: ReadySession): Promise<void> {
    this.#attempt = 0;
    this.#o.outbound.session({
      durability: ready.durability,
      maxMessageBytes: ready.maxMessageBytes,
    });
    for (const ctx of this.#resources.values()) if (ctx.wanted) await this.#sendOpen(ctx);
  }

  async #onClosed(reason: string): Promise<void> {
    this.#emit({ type: "connection", state: "DISCONNECTED", reason });
    for (const r of this.#requests.values())
      if (r.kind === "host")
        r.reject(new Error(`the connection closed before RESOURCE_HOSTED: ${reason}`));
    this.#requests.clear();
    for (const ctx of this.#resources.values()) {
      this.#move(ctx, "CLOSE"); // §65, G-SM1: every Resource closes with the connection
      ctx.view = null;
    }
    await this.#o.outbound.connectionLost(iso(this.#o.now()));
    if (this.#stopped) return;
    this.#attempt += 1;
    const delay = (this.#o.reconnect ?? defaultReconnect)(this.#attempt);
    this.#reconnectAt = delay === null ? null : this.#o.now() + delay;
  }

  async #sendOpen(ctx: ResourceContext): Promise<void> {
    if (ctx.state !== "CLOSED") return;
    const R = ctx.binding.resourceId;
    const chain = await loadControlChain(this.#o.storage, R);
    const heads: ControlHeadRef[] =
      chain?.kind === "linear" ? [{ seq: chain.state.seq, recordId: chain.state.head }] : [];
    const have = (await resourceSyncState(this.#o.storage, R)).have;
    ctx.fetched = [];
    ctx.controlTarget = null;
    ctx.early = [];
    this.#request(
      { kind: "open", resource: toHex(R) },
      createMessage("RESOURCE_OPEN", {
        resourceId: R,
        heads,
        haves: haveToLive(have),
        flags: SUBSCRIBE_DATA_AND_CONTROL,
      }),
    );
    this.#move(ctx, "OPEN");
  }

  // -------------------------------------------------------------------------
  // inbound

  async #onMessage(m: AnyMessage): Promise<void> {
    const request =
      m.correlationId === undefined ? undefined : this.#requests.get(toHex(m.correlationId));
    switch (m.type) {
      case "RESOURCE_HOSTED":
        if (request?.kind === "host") {
          this.#requests.delete(toHex(m.correlationId as Uint8Array));
          request.resolve(m.body.durability);
        }
        return;
      case "RESOURCE_OPENED": {
        const ctx = this.#ctx(m.body.resourceId);
        if (ctx === undefined || ctx.state !== "OPENING") return;
        this.#done(m);
        ctx.remoteHave = normalizeLiveHaves(m.body.haves);
        ctx.offered = m.body.snapshot ?? null;
        this.#move(ctx, "OPENED");
        await this.#controlRound(ctx, m.body.heads);
        return;
      }
      case "CONTROL_HAVE": {
        const ctx = this.#ctx(m.body.resourceId);
        this.#done(m);
        if (ctx !== undefined && ctx.state === "LIVE")
          await this.#onControlHeads(ctx, m.body.heads);
        return;
      }
      case "CONTROL_BATCH": {
        const ctx = this.#ctx(m.body.resourceId);
        if (ctx === undefined) return;
        const solicited = request?.kind === "control";
        if (!solicited && ctx.state === "LIVE") this.#move(ctx, "CONTROL_RECORD"); // a live push (§65)
        if (ctx.state !== "CONTROL_SYNC") {
          // A push during key or data sync: validated in place.
          if (ctx.view !== null && !solicited)
            await this.#onControlRecords(ctx, m.body.objects, true);
          return;
        }
        await this.#onControlRecords(ctx, m.body.objects, solicited);
        return;
      }
      case "KEY_PACKAGE_BATCH": {
        const ctx = this.#ctx(m.body.resourceId);
        this.#done(m);
        if (ctx !== undefined) await this.#onKeyPackages(ctx, m.body.objects);
        return;
      }
      case "DATA_BATCH": {
        const ctx = this.#ctx(m.body.resourceId);
        if (ctx !== undefined) await this.#onUnits(ctx, m.body.objects);
        return;
      }
      case "SNAPSHOT": {
        const ctx = this.#ctx(m.body.resourceId);
        this.#done(m);
        if (ctx !== undefined && ctx.snapshotPending) await this.#onSnapshot(ctx, m.body.snapshot);
        return;
      }
      case "DATA_HAVE": {
        const ctx = this.#ctx(m.body.resourceId);
        this.#done(m);
        if (ctx === undefined) return;
        ctx.remoteHave = normalizeLiveHaves(m.body.haves);
        if (ctx.state === "LIVE") await this.#dataRound(ctx);
        return;
      }
      case "ACK":
        if (request !== undefined) {
          this.#done(m);
          return;
        }
        await this.#onAck(m);
        return;
      case "NACK":
        if (request !== undefined) {
          this.#done(m);
          this.#onRequestNack(request, m);
          return;
        }
        await this.#onNack(m);
        return;
      case "ERROR":
        this.#error(`ERROR ${m.body.code}`, m.body.diagnostic ?? "the server reported an error");
        return;
      default:
        return; // PONG and anything this client does not use
    }
  }

  /** Forgets the request a reply answers (multi-batch replies keep it until the round ends). */
  #done(m: AnyMessage): void {
    if (m.correlationId !== undefined && m.type !== "CONTROL_BATCH" && m.type !== "DATA_BATCH")
      this.#requests.delete(toHex(m.correlationId));
  }

  #onRequestNack(request: Request, m: LfcpMessage<"NACK">): void {
    const code = String(m.body.code);
    if (request.kind === "host") {
      request.reject(
        new Error(
          `RESOURCE_HOST refused: NACK ${code}${m.body.diagnostic ? ` (${m.body.diagnostic})` : ""}`,
        ),
      );
      return;
    }
    const ctx = this.#resources.get(request.resource);
    this.#error(
      `NACK ${code}`,
      `${request.kind} refused${m.body.diagnostic ? `: ${m.body.diagnostic}` : ""}`,
      ctx?.binding.resourceId,
    );
    if (ctx === undefined) return;
    if (request.kind === "open") this.#move(ctx, "CLOSE");
    if (request.kind === "keys") this.#keyBlocked(ctx);
  }

  // -------------------------------------------------------------------------
  // Control (§44-§47, §67)

  async #onControlHeads(ctx: ResourceContext, heads: readonly ControlHeadRef[]): Promise<void> {
    const chain = await loadControlChain(this.#o.storage, ctx.binding.resourceId);
    const local = chain?.kind === "linear" ? localControlOf(chain) : null;
    const plan = planControlSync(local, heads);
    if (plan.kind === "in-sync" || plan.kind === "peer-behind" || plan.kind === "peer-empty")
      return;
    this.#move(ctx, "CONTROL_RECORD");
    await this.#controlRound(ctx, heads);
  }

  async #controlRound(ctx: ResourceContext, heads: readonly ControlHeadRef[]): Promise<void> {
    const R = ctx.binding.resourceId;
    const chain = await loadControlChain(this.#o.storage, R);
    const local = chain?.kind === "linear" ? localControlOf(chain) : null;
    const plan = planControlSync(local, heads);
    ctx.fetched = [];
    if (plan.kind === "fetch" || plan.kind === "fork") {
      const range = plan.kind === "fetch" ? plan : plan.fetch;
      ctx.controlTarget = range.end;
      this.#request(
        { kind: "control", resource: toHex(R) },
        createMessage("CONTROL_GET", { resourceId: R, start: range.start, end: range.end }),
      );
      return;
    }
    if (chain?.kind !== "linear") {
      this.#error("INVALID_CONTROL_CHAIN", "no valid local Control Chain and nothing to fetch", R);
      return;
    }
    await this.#controlComplete(ctx, chain);
  }

  async #onControlRecords(
    ctx: ResourceContext,
    records: readonly Uint8Array[],
    solicited: boolean,
  ): Promise<void> {
    const R = ctx.binding.resourceId;
    const stored = await loadControlChain(this.#o.storage, R);
    const storedRecords =
      stored?.kind === "linear" ? stored.records.map((r) => r.signed.bytes) : [];
    const localSeq = stored?.kind === "linear" ? stored.state.seq : -1n;
    if (!solicited) {
      // A pushed record that does not continue our chain: fetch the gap first.
      const seqs = records.map((r) => parseControlRecord(r).payload.controlSeq);
      const min = seqs.reduce((a, b) => (b < a ? b : a), seqs[0] ?? 0n);
      const max = seqs.reduce((a, b) => (b > a ? b : a), seqs[0] ?? 0n);
      ctx.controlTarget = max;
      if (min > localSeq + 1n) {
        ctx.fetched = [...records];
        this.#request(
          { kind: "control", resource: toHex(R) },
          createMessage("CONTROL_GET", { resourceId: R, start: localSeq + 1n, end: max }),
        );
        return;
      }
    }
    ctx.fetched.push(...records);
    const byId = new Map<string, Uint8Array>();
    for (const b of [...storedRecords, ...ctx.fetched])
      byId.set(toHex(parseControlRecord(b).signed.id), b);
    const ordered = [...byId.values()]
      .map((b) => ({ b, p: parseControlRecord(b) }))
      .sort((x, y) =>
        x.p.payload.controlSeq < y.p.payload.controlSeq
          ? -1
          : x.p.payload.controlSeq > y.p.payload.controlSeq
            ? 1
            : toHex(x.p.signed.id) < toHex(y.p.signed.id)
              ? -1
              : 1,
      )
      .map((x) => x.b);
    const result = validateControlChain(ordered);
    if (result.kind === "conflict") {
      await saveControlConflict(this.#o.storage, R, result);
      if (ctx.state === "CONTROL_SYNC") this.#move(ctx, "FORK");
      this.#emit({ type: "control-conflict", resourceId: R, heads: result.competing });
      return;
    }
    if (result.kind === "invalid") {
      // Several replies may still be on their way; an incomplete chain is not yet invalid.
      if (
        result.problem === "MALFORMED" ||
        result.problem === "UNSUPPORTED_TYPE" ||
        ctx.controlTarget === null
      ) {
        this.#error(
          result.wireCode,
          `the server's Control Records do not validate (${result.problem})`,
          R,
        );
      }
      return;
    }
    if (ctx.controlTarget !== null && result.state.seq < ctx.controlTarget) return; // more batches to come
    const saved = await saveControlChain(
      this.#o.storage,
      result,
      stored?.kind === "linear" ? stored.state.head : null,
    );
    if (!saved.ok) {
      this.#error("CONTROL_HEAD_MISMATCH", "the stored Control Head moved during sync", R);
      return;
    }
    for (const [k, r] of this.#requests)
      if (r.kind === "control" && r.resource === toHex(R)) this.#requests.delete(k);
    ctx.fetched = [];
    ctx.controlTarget = null;
    await this.#controlComplete(ctx, result, stored?.kind === "linear" ? stored : null);
  }

  /** A newly validated Control state: reconcile epochs (G-EP7, §88 step 7), release queued puts, then keys. */
  async #controlComplete(
    ctx: ResourceContext,
    chain: Extract<ChainResult, { kind: "linear" }>,
    previous: Extract<ChainResult, { kind: "linear" }> | null = null,
  ): Promise<void> {
    const R = ctx.binding.resourceId;
    const before = previous ?? ctx.view;
    ctx.view = chain;
    const epochsChanged =
      before === null ||
      [...chain.state.epochs.values()].some((e) => {
        const old = before.state.epochs.get(String(e.epoch));
        return old === undefined || (old.closedBy === null) !== (e.closedBy === null);
      });
    if (epochsChanged) {
      const applied = await ctx.binding.applier.reconcileEpochs(chain);
      const outbound = await this.#o.outbound.reconcileEpochs(chain);
      if (applied.snapshotDropped) ctx.covered = []; // SNAP-EP: covered units are fetched again
      if (applied.excluded.length > 0 || outbound.length > 0 || applied.snapshotDropped) {
        ctx.binding.checkpointer?.noteChange();
        this.#emit({ type: "epoch-reconciled", resourceId: R, applied, outbound });
      }
    }
    await this.#o.outbound.controlSynced(R);
    if (ctx.state === "CONTROL_SYNC") {
      this.#move(ctx, "CONTROL_COMPLETE");
      this.#requestKeys(ctx, this.#o.now());
    } else if (ctx.state === "KEY_BLOCKED" && epochsChanged) {
      this.#requestKeys(ctx, this.#o.now());
    }
  }

  // -------------------------------------------------------------------------
  // Keys (§52, §53, §66 step 2)

  async #epochsWithoutDek(ctx: ResourceContext): Promise<DataEpoch[]> {
    const rows = await this.#o.storage.control.epochs(ctx.binding.resourceId);
    const out: DataEpoch[] = [];
    for (const e of ctx.view?.state.epochs.values() ?? []) {
      const row = rows.find((r) => r.epoch === e.epoch);
      if (row?.dekRef == null || (await this.#o.secrets.get(row.dekRef)) === undefined)
        out.push(dataEpoch(e.epoch));
    }
    return out;
  }

  #requestKeys(ctx: ResourceContext, now: number): void {
    this.#serial(async () => {
      if (ctx.view === null || (ctx.state !== "KEY_SYNC" && ctx.state !== "KEY_BLOCKED")) return;
      const missing = await this.#epochsWithoutDek(ctx);
      if (missing.length === 0) {
        if (ctx.state === "KEY_BLOCKED") this.#move(ctx, "PACKAGE_ARRIVED");
        this.#move(ctx, "DEK_AVAILABLE");
        await this.#startData(ctx);
        return;
      }
      ctx.missingEpochs = missing;
      ctx.lastKeyRequest = now;
      const R = ctx.binding.resourceId;
      this.#request(
        { kind: "keys", resource: toHex(R) },
        createMessage("KEY_PACKAGE_GET", {
          resourceId: R,
          recipient: this.#o.signer.descriptor.principalId,
          epochs: missing,
        }),
      );
    });
  }

  async #onKeyPackages(ctx: ResourceContext, packages: readonly Uint8Array[]): Promise<void> {
    const view = ctx.view;
    if (view === null) return;
    const R = ctx.binding.resourceId;
    const recipient = { descriptor: this.#o.signer.descriptor, agreement: this.#o.agreement };
    for (const bytes of packages) {
      const r = await receiveKeyPackage(view, bytes, recipient);
      if (r.kind !== "opened") {
        this.#error(
          r.kind === "rejected" ? r.wireCode : r.code,
          `a Key Package was not used (${r.kind})`,
          R,
        );
        continue;
      }
      // Secret first, then the row that references it (LFCP-034).
      const ref = dekSecretRef(R, r.epoch);
      await this.#o.secrets.put(ref, exportSecretKeyBytes(r.dek));
      const row = (await this.#o.storage.control.epochs(R)).find((e) => e.epoch === r.epoch);
      if (row !== undefined) {
        const next: EpochRow = { ...row, dekRef: ref };
        await this.#o.storage.commit([{ op: "put-epoch", resourceId: R, epoch: next }]);
      }
    }
    const missing = await this.#epochsWithoutDek(ctx);
    const current = view.state.epoch.epoch;
    if (missing.some((e) => e === current)) {
      this.#keyBlocked(ctx);
      return;
    }
    if (missing.length > 0) this.#emit({ type: "key-blocked", resourceId: R, epochs: missing }); // older epochs: their units wait
    if (ctx.state === "KEY_BLOCKED") this.#move(ctx, "PACKAGE_ARRIVED");
    if (ctx.state === "KEY_SYNC") {
      this.#move(ctx, "DEK_AVAILABLE");
      await this.#startData(ctx);
    }
  }

  #keyBlocked(ctx: ResourceContext): void {
    if (ctx.state === "KEY_SYNC") this.#move(ctx, "KEY_UNAVAILABLE");
    this.#emit({
      type: "key-blocked",
      resourceId: ctx.binding.resourceId,
      epochs: ctx.missingEpochs,
    });
  }

  // -------------------------------------------------------------------------
  // Data (§48-§51, §68, §69)

  async #startData(ctx: ResourceContext): Promise<void> {
    // Accepted units on disk that the profile state lacks (a crash before
    // the checkpoint caught up) are applied again before any new unit.
    if (ctx.view !== null) {
      const r = await ctx.binding.applier.replayStored(ctx.view);
      if (r.replayed.length > 0 || r.skipped.length > 0) {
        ctx.binding.checkpointer?.noteChange();
        this.#emit({ type: "replayed", resourceId: ctx.binding.resourceId, ...r });
      }
    }
    await this.#flush(ctx); // §88 step 6: upload locally queued valid units
    if (await this.#snapshotUseful(ctx)) {
      // §66 step 3: the preferred Snapshot first, then the units beyond it.
      const R = ctx.binding.resourceId;
      ctx.snapshotPending = true;
      this.#request(
        { kind: "snapshot", resource: toHex(R) },
        createMessage("SNAPSHOT_GET", {
          resourceId: R,
          snapshotId: (ctx.offered as SnapshotSummary).snapshotId,
        }),
      );
      return;
    }
    await this.#afterSnapshot(ctx);
  }

  async #afterSnapshot(ctx: ResourceContext): Promise<void> {
    ctx.snapshotPending = false;
    const early = ctx.early;
    ctx.early = [];
    await this.#dataRound(ctx);
    if (early.length > 0) await this.#onUnits(ctx, early);
  }

  /** The offered Snapshot holds units we lack, we can load it, and we did not load it before. */
  async #snapshotUseful(ctx: ResourceContext): Promise<boolean> {
    const offered = ctx.offered;
    if (offered === null || ctx.binding.snapshot === undefined) return false;
    if ((await this.#o.storage.snapshots.get(offered.snapshotId)) !== undefined) return false;
    const local = (await resourceSyncState(this.#o.storage, ctx.binding.resourceId)).have;
    return missingFrom(local, normalizeLiveHaves(offered.frontier)).length > 0;
  }

  async #onSnapshot(ctx: ResourceContext, bytes: Uint8Array): Promise<void> {
    const R = ctx.binding.resourceId;
    const view = ctx.view;
    const binding = ctx.binding.snapshot;
    if (view !== null && binding !== undefined) {
      const r = await receiveSnapshot(view, bytes, {
        dek: dekResolver(this.#o.storage, this.#o.secrets, R),
        profile: binding.codec,
      });
      if (r.kind === "accepted") {
        binding.load(r.value);
        const frontier = encode(canonicalFrontierToCbor(r.frontier));
        await this.#o.storage.commit([
          {
            op: "put-snapshot",
            row: {
              snapshotId: r.snapshotId,
              resourceId: R,
              dataEpoch: r.epoch,
              publisher: r.publisher,
              snapshotSeq: r.seq,
              frontier,
              bytes,
            },
          },
        ]);
        ctx.binding.checkpointer?.noteChange();
        this.#emit({
          type: "snapshot-loaded",
          resourceId: R,
          snapshotId: r.snapshotId,
          frontier: r.frontier,
        });
      } else {
        const code = r.kind === "local-failure" ? r.reason : r.wireCode;
        this.#error(
          code,
          `the offered Snapshot was not loaded (${r.kind}); replaying units instead`,
          R,
        );
      }
    }
    await this.#afterSnapshot(ctx);
  }

  /**
   * Publishes a Snapshot of the Resource's current state (§29): its frontier
   * is every merged unit and every stored Snapshot's frontier, so a client
   * that loads it never skips content the state does not hold. Queued and
   * sent like any object; returns its ID.
   */
  async publishSnapshot(resource: ResourceId): Promise<Hash32> {
    const ctx = this.#resources.get(toHex(resource));
    if (ctx === undefined)
      throw new LfcpError("UNSUPPORTED_VALUE", "the Resource is not open here");
    let id: Hash32 | undefined;
    await new Promise<void>((resolve, reject) =>
      this.#serial(async () => {
        try {
          id = await this.#publish(ctx);
          resolve();
        } catch (e) {
          reject(e);
        }
      }),
    );
    return id as Hash32;
  }

  async #publish(ctx: ResourceContext): Promise<Hash32> {
    const R = ctx.binding.resourceId;
    const binding = ctx.binding.snapshot;
    const view = ctx.view;
    if (binding === undefined || view === null)
      throw new LfcpError(
        "UNSUPPORTED_VALUE",
        "no Snapshot binding, or the Control Chain is not synchronized",
      );
    const dek = await dekResolver(this.#o.storage, this.#o.secrets, R)(view.state.epoch.epoch);
    if (dek === undefined) throw new LfcpError("UNSUPPORTED_VALUE", "no DEK for the current epoch");
    let frontier = await snapshotFrontier(this.#o.storage, R);
    for (const u of await this.#o.storage.dataUnits.withStatus(R, "merged"))
      if (u.accepted) frontier = addSequence(frontier, u.actor, u.actorSeq);
    const created = await createQueuedSnapshot(this.#o.storage, {
      view,
      controlHead: view.state.head,
      publisher: this.#o.signer,
      dek,
      frontier: haveToLive(frontier),
      profile: binding.codec,
      value: binding.current(),
    });
    ctx.unitsSinceSnapshot = 0;
    this.#emit({ type: "snapshot-published", resourceId: R, snapshotId: created.snapshotId });
    await this.#flush(ctx);
    return created.snapshotId;
  }

  async #dataRound(ctx: ResourceContext): Promise<void> {
    const R = ctx.binding.resourceId;
    ctx.covered = await snapshotFrontier(this.#o.storage, R);
    const local = (await resourceSyncState(this.#o.storage, R)).have;
    // Beyond a loaded Snapshot's frontier (missingAfter: `local` includes it),
    // plus each actor's last covered unit, so the next one links (§26.2).
    const missing = [...(await this.#boundary(ctx)), ...missingFrom(local, ctx.remoteHave)];
    if (missing.length === 0) {
      ctx.lastRound = "";
      if (ctx.state === "DATA_SYNC") this.#move(ctx, "FRONTIER_REACHED");
      ctx.expected = [];
      ctx.received = [];
      return;
    }
    // A round that asks again for exactly what the last one asked for made no
    // progress (e.g. the server lacks units it announced): stop instead of
    // looping; periodic anti-entropy tries again.
    const key = missing.map((r) => `${toHex(r.actor)}:${r.start}-${r.end}`).join(",");
    if (key === ctx.lastRound) {
      ctx.lastRound = "";
      this.#error(
        "NO_PROGRESS",
        "a data round fetched nothing new; will retry on the next DATA_HAVE",
        R,
      );
      if (ctx.state === "DATA_SYNC") this.#move(ctx, "FRONTIER_REACHED");
      ctx.expected = [];
      ctx.received = [];
      return;
    }
    ctx.lastRound = key;
    if (ctx.state === "LIVE") this.#move(ctx, "MISSING_RANGES");
    let expected: HaveVector = [];
    for (const r of missing)
      for (let s = r.start; s <= r.end; s++) expected = addSequence(expected, r.actor, s);
    ctx.expected = expected;
    ctx.received = [];
    for (const batch of batchDataRanges(missing))
      this.#request(
        { kind: "data-get", resource: toHex(R) },
        createMessage("DATA_GET", {
          resourceId: R,
          ranges: batch.map((r) => ({ actor: r.actor, start: r.start, end: r.end })),
        }),
      );
  }

  /** The last unit of each actor run a stored Snapshot covers, when we do not hold it yet. */
  async #boundary(ctx: ResourceContext): Promise<ActorRange[]> {
    const R = ctx.binding.resourceId;
    const out: ActorRange[] = [];
    for (const h of ctx.covered)
      for (const seq of [
        ...(h.contiguous > 0n ? [h.contiguous] : []),
        ...h.extras.map(([, end]) => end),
      ]) {
        if (!hasSequence(ctx.remoteHave, h.principalId, seq)) continue;
        if (
          (await this.#o.storage.dataUnits.acceptedAt(R, h.principalId, actorSequence(seq))) !==
          undefined
        )
          continue;
        out.push({ actor: h.principalId, start: seq, end: seq });
      }
    return out;
  }

  async #onUnits(ctx: ResourceContext, units: readonly Uint8Array[]): Promise<void> {
    const view = ctx.view;
    if (
      view === null ||
      ctx.state === "KEY_SYNC" ||
      ctx.state === "KEY_BLOCKED" ||
      ctx.state === "CONTROL_SYNC" ||
      ctx.snapshotPending
    ) {
      ctx.early.push(...units);
      return;
    }
    const R = ctx.binding.resourceId;
    let changed = false;
    let needControl = false;
    for (const bytes of units) {
      let covered = false;
      try {
        const p = parseDataUnit(bytes).payload;
        ctx.received = addSequence(ctx.received, p.actor, p.actorSeq);
        covered = hasSequence(ctx.covered, p.actor, p.actorSeq);
      } catch {
        // malformed: the applier reports it
      }
      const outcome = covered
        ? await ctx.binding.applier.acceptCovered(view, bytes)
        : await ctx.binding.applier.receive(view, bytes);
      if (outcome.kind === "applied" || outcome.kind === "profile-pending") {
        changed = true;
        ctx.unitsSinceSnapshot += 1;
      }
      if (outcome.kind === "rejected" && outcome.wireCode === "MISSING_DEPENDENCY")
        needControl = true;
      this.#emit({ type: "unit", resourceId: R, outcome });
      // Held units this one released (§26.2): their outcomes too.
      const released = "released" in outcome ? outcome.released : [];
      for (const r of released) {
        if (r.kind === "applied" || r.kind === "profile-pending") changed = true;
        this.#emit({ type: "unit", resourceId: R, outcome: r });
      }
    }
    if (changed) ctx.binding.checkpointer?.noteChange();
    if (needControl) this.#refreshControl(ctx);
    if (
      ctx.state === "DATA_SYNC" &&
      ctx.expected.length > 0 &&
      missingFrom(ctx.received, ctx.expected).length === 0
    ) {
      ctx.expected = [];
      await this.#dataRound(ctx);
    }
  }

  #sendHave(ctx: ResourceContext, now: number): void {
    ctx.lastHave = now;
    this.#serial(async () => {
      const R = ctx.binding.resourceId;
      const have = (await resourceSyncState(this.#o.storage, R)).have;
      this.#request(
        { kind: "data-have", resource: toHex(R) },
        createMessage("DATA_HAVE", { resourceId: R, haves: haveToLive(have) }),
      );
    });
  }

  #refreshControl(ctx: ResourceContext): void {
    this.#serial(async () => {
      const R = ctx.binding.resourceId;
      const chain = await loadControlChain(this.#o.storage, R);
      const heads: ControlHeadRef[] =
        chain?.kind === "linear" ? [{ seq: chain.state.seq, recordId: chain.state.head }] : [];
      this.#request(
        { kind: "control", resource: toHex(R) },
        createMessage("CONTROL_HAVE", { resourceId: R, heads }),
      );
    });
  }

  // -------------------------------------------------------------------------
  // Outbound (§51, §54, §57, §59, §60, §88)

  async #flush(ctx: ResourceContext): Promise<void> {
    if (this.#connection.state !== "READY") return;
    if (ctx.state !== "DATA_SYNC" && ctx.state !== "LIVE") return;
    const messages = await this.#o.outbound.next(ctx.binding.resourceId, iso(this.#o.now()));
    for (const m of messages) this.#connection.sendEncoded(m.bytes);
  }

  async #onAck(m: LfcpMessage<"ACK">): Promise<void> {
    const outcome = await this.#o.outbound.onAck(m, iso(this.#o.now()));
    this.#emit({ type: "ack", outcome });
    // Our own Control Record was committed: catch up, since the server does not push it back to us.
    if (m.body.requestType === MESSAGE_TYPE.CONTROL_PUT && outcome.acked.length > 0)
      for (const ctx of this.#resources.values())
        if (ctx.state === "LIVE") this.#refreshControl(ctx);
  }

  async #onNack(m: LfcpMessage<"NACK">): Promise<void> {
    const outcome = await this.#o.outbound.onNack(m, iso(this.#o.now()));
    this.#emit({ type: "nack", outcome });
    if (outcome.kind === "needs-control-sync")
      for (const ctx of this.#resources.values())
        if (ctx.state === "LIVE") this.#refreshControl(ctx);
  }
}

/**
 * A thin timer driver for SyncClient: calls tick(now) every `intervalMs`
 * with the given clock and timer functions (setInterval/clearInterval in
 * production). Returns the stop function. The core never sets timers
 * itself; this is the one explicit place that does.
 */
export function startSyncDriver(
  client: SyncClient,
  timers: {
    readonly setInterval: (fn: () => void, ms: number) => unknown;
    readonly clearInterval: (handle: unknown) => void;
    readonly now: () => number;
  },
  intervalMs = 1000,
): () => void {
  const handle = timers.setInterval(() => client.tick(timers.now()), intervalMs);
  return () => timers.clearInterval(handle);
}
