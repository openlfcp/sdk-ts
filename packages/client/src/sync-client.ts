import {
  actorSequence,
  type ControlRecordId,
  type DataEpoch,
  type DataUnitId,
  dataEpoch,
  type Hash32,
  hash32,
  LfcpError,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import { type AgreementKeyPair, exportSecretKeyBytes, sha256 } from "@openlfcp/crypto";
import {
  dekSecretRef,
  type EpochRow,
  type LfcpStorage,
  type SecretStore,
  type StorageWrite,
  type StoredDataUnit,
} from "@openlfcp/storage";
import {
  type ActorRange,
  type AnyMessage,
  addRange,
  addSequence,
  batchDataRanges,
  type ChainResult,
  type ClientConnectionState,
  type ControlHeadRef,
  canonicalFrontierToCbor,
  createMessage,
  type DataProfileCodec,
  ERROR_CODE,
  type HaveVector,
  hasSequence,
  haveDifference,
  type LfcpMessage,
  type LiveActorHave,
  localControlOf,
  MESSAGE_TYPE,
  missingFrom,
  normalizeLiveHaves,
  parseControlRecord,
  parseDataUnit,
  parseKeyPackage,
  planControlSync,
  type ReadySession,
  receiveKeyPackage,
  receiveSnapshot,
  type Signer,
  type SnapshotSummary,
  validateControlChain,
} from "@openlfcp/wire";
import { encode } from "@openlfcp/wire/cbor";
import {
  afterAccepted,
  afterMismatch,
  RECOVERY_TRANSIENT_ATTEMPTS,
  RECOVERY_TRANSIENT_CODES,
  type RecoveryStep,
  startRecovery,
} from "./access-recovery.js";
import type { ApplyOutcome, DataUnitApplier, EpochReconciliation } from "./apply.js";
import type { ProfileCheckpointer } from "./checkpoint.js";
import { LfcpConnection, type WebSocketFactory } from "./connection.js";
import { EngineGuard, isEngineTrap, snapshotItem } from "./engine-guard.js";
import type { AckOutcome, NackOutcome, OutboundQueue, StaleOutboundUnit } from "./outbound.js";
import { resourceSyncState, snapshotFrontier } from "./outbound.js";
import { createQueuedSnapshot } from "./queue.js";
import {
  type ResourcePhase,
  type ResourcePhaseEvent,
  resourcePhaseTransition,
} from "./resource-state.js";
import {
  adoptStoredDeks,
  dekResolver,
  loadControlChain,
  saveControlChain,
  saveControlConflict,
} from "./storage.js";

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
  /**
   * How long a request waits for its answer on a live connection before
   * the step it belongs to is issued again (a lost request or reply, §70
   * at-least-once): RESOURCE_OPEN, the Control round, KEY_PACKAGE_GET, the
   * data round. A lost SNAPSHOT_GET falls back to the data round. Default 15 s.
   */
  readonly requestTimeoutMs?: number;
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
      /** Units quarantined because they crashed the profile engine twice by themselves. */
      readonly crashed: readonly DataUnitId[];
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
    }
  /**
   * The server answered RESOURCE_OPEN with RESOURCE_NOT_HOSTED although it
   * hosted the Resource before (it lost it, e.g. restored from an older
   * store): the client hosted it again from its Genesis (§41.1), or the
   * server refused that ("refused", with the §62 code; the Resource is then
   * refused for good, see resource-refused).
   */
  | {
      readonly type: "rehost";
      readonly resourceId: ResourceId;
      readonly url: string;
      readonly outcome: "hosted" | "refused";
      readonly code?: string;
    }
  /**
   * RESOURCE_OPEN was refused with AUTHORIZATION_FAILED although this
   * client's validated chain grants it data/read: the server may have lost
   * Control Records in a restore (LFCP-02-106). "started": the client
   * re-supplies its chain with CONTROL_PUT; "recovered": the server opened
   * the Resource again after it; "ended": no recovery, with the reason (see
   * RecoveryEnd, or "still-refused" when the server holds our chain and
   * still refuses), and the refusal stands.
   */
  | {
      readonly type: "access-recovery";
      readonly resourceId: ResourceId;
      readonly url: string;
      readonly outcome: "started" | "recovered" | "ended";
      readonly reason?: string;
    }
  /**
   * The server refused the Resource for good (see ResourceRefusal): it is
   * CLOSED and is not opened again until open() is called for it.
   */
  | {
      readonly type: "resource-refused";
      readonly resourceId: ResourceId;
      readonly refusal: ResourceRefusal;
    };

/**
 * Why a server will not sync a Resource with this session, from a NACK
 * whose code no retry can change (TERMINAL_RESOURCE_CODES): the server does
 * not host it (§41: purged, never hosted, a restored server), it was
 * tombstoned (§24), the session Principal may not read it (§41, §84: never
 * granted or revoked), or the request itself is not acceptable to it. The
 * Resource stays CLOSED; open() asks again.
 */
export interface ResourceRefusal {
  /** The §62 name, e.g. RESOURCE_NOT_HOSTED. */
  readonly code: string;
  /** The server's diagnostic, if any (never key material, §60). */
  readonly diagnostic?: string;
  /** The server that refused (the session URL). */
  readonly url: string;
  /** Which request was refused: "open", "control", "keys", "data-get", "data-have" or "snapshot". */
  readonly request: string;
}

/**
 * §62 codes that end syncing a Resource on this server when they refuse
 * RESOURCE_OPEN or one of its reads (CONTROL_GET, KEY_PACKAGE_GET, DATA_GET,
 * DATA_HAVE, SNAPSHOT_GET). Repeating the same request cannot change them:
 * the server's hosting or the Resource's Control state must change first,
 * and the application decides when to ask again. Every other code is
 * transient for these requests (RATE_LIMITED, INTERNAL_ERROR, QUOTA_EXCEEDED,
 * unknown codes) and is retried with the ReconnectPolicy's backoff, except
 * where the request has its own fallback: KEY_PACKAGE_GET → KEY_BLOCKED,
 * SNAPSHOT_GET → replaying the units (§29.2).
 */
export const TERMINAL_RESOURCE_CODES: ReadonlySet<string> = new Set([
  "RESOURCE_NOT_HOSTED",
  "RESOURCE_NOT_FOUND",
  "RESOURCE_TOMBSTONED",
  "AUTHORIZATION_FAILED",
  "PROTOCOL_UNSUPPORTED",
  "MALFORMED_MESSAGE",
  "PROFILE_UNSUPPORTED",
]);

const NACK_NAME = new Map<bigint, string>(Object.entries(ERROR_CODE).map(([k, v]) => [v, k]));

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
      readonly genesis: Uint8Array;
      readonly resolve: (durability: bigint) => void;
      readonly reject: (error: Error) => void;
    }
  /** RESOURCE_HOST of a Resource the server lost (§41.1). */
  | { readonly kind: "rehost"; readonly resource: string }
  /** CONTROL_PUT of record `index` of our chain, re-supplying access (LFCP-02-106). */
  | { readonly kind: "recover-control"; readonly resource: string; readonly index: number }
  /** Objects the server lacks, uploaded again (§68.1): their answers concern no queued item. */
  | { readonly kind: "offer-control"; readonly resource: string }
  | {
      readonly kind: "offer-data";
      readonly resource: string;
      readonly units: readonly { readonly id: string; readonly bytes: Uint8Array }[];
    }
  | { readonly kind: "offer-keys"; readonly resource: string };

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
  /** The server heads the current Control round works towards (to issue it again). */
  lastHeads: readonly ControlHeadRef[];
  /**
   * One of our Control Records was committed while the Resource was not
   * LIVE (e.g. mid Control sync, which may have read the heads before
   * it): the Control state is refreshed once it is LIVE again, since the
   * server never pushes our own records back to us.
   */
  controlStale: boolean;
  /** Refused for good by the server (TERMINAL_RESOURCE_CODES); cleared by open(). */
  refusal: ResourceRefusal | null;
  /** Transient refusals in a row, for the reopen backoff; reset on LIVE. */
  refusedAttempt: number;
  /** When to open again after a transient refusal (caller's clock), or null. */
  reopenAt: number | null;
  /** Units offered to the server and not yet answered (§68.1), by unit ID hex. */
  offering: Set<string>;
  /** Key Packages were offered again since the Resource was opened (§68.1). */
  keysOffered: boolean;
  /** Re-hosted since it was last LIVE (§41.1): a second RESOURCE_NOT_HOSTED is final. */
  rehosted: boolean;
  /**
   * Access recovery ran in this session (LFCP-02-106): a second
   * AUTHORIZATION_FAILED on open is final. Reset on LIVE and on a new
   * connection.
   */
  recoveryTried: boolean;
  /** Transient refusals of the current access recovery. */
  recoveryAttempts: number;
  /** A recovery pushed our chain and opened again: the next open answer ends it. */
  recoveryReopened: boolean;
}

/**
 * Data Unit statuses whose units this client has accepted and may offer to
 * a server that lacks them (§68.1): never a unit held for its `previous`
 * link, a quarantined or equivocating one, or one that failed locally.
 */
const OFFERABLE = [
  "merged",
  "profile-pending",
  "profile-held",
  "profile-rejected",
  "profile-unsupported",
  "seen",
] as const;

/** At most this many objects per offered DATA_PUT or KEY_PACKAGE_PUT. */
const OFFER_BATCH = 64;

/** The local mark that a route hosted (or opened) a Resource for this client (§41.1). */
const hostedMark = (resource: Uint8Array, url: string) => `hosted-route:${toHex(resource)}:${url}`;

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
  /** When each request was sent (caller's clock), for the request timeout. */
  readonly #sentAt = new Map<string, number>();
  readonly #requestTimeoutMs: number;
  readonly #listeners = new Set<(event: SyncEvent) => void>();
  readonly #antiEntropyMs: number;
  /** The crash-loop breaker for Snapshot loads (EngineGuard). */
  readonly #snapshots: EngineGuard;
  #stopped = true;
  /** The profile engine trapped: nothing more is processed (ENGINE_TRAP). */
  #trapped = false;
  #attempt = 0;
  #reconnectAt: number | null = null;
  /** READY's maximum message size, for offered batches (§31). */
  #maxMessageBytes = 8 * 1024 * 1024;
  /** Serializes message handling: each message is handled after the previous one finished. */
  #queue: Promise<void> = Promise.resolve();

  constructor(options: SyncClientOptions) {
    this.#o = options;
    this.#snapshots = new EngineGuard(options.storage, "snapshots");
    this.#antiEntropyMs = options.antiEntropyMs ?? 30_000;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
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
    this.#queue = this.#queue
      .then(() => (this.#trapped ? undefined : fn()))
      .catch((e: unknown) => {
        if (!isEngineTrap(e)) {
          this.#emit({
            type: "error",
            code: "INTERNAL",
            message: e instanceof Error ? e.message : String(e),
          });
          return;
        }
        // The profile engine trapped: in this process it is gone for good.
        // Stop once, loudly; the crash-loop breaker takes over at the next start.
        if (this.#trapped) return;
        this.#trapped = true;
        this.#stopped = true;
        this.#reconnectAt = null;
        this.#connection.close("the profile engine trapped");
        this.#emit({
          type: "error",
          code: "ENGINE_TRAP",
          message: `the profile engine trapped (${e instanceof Error ? e.message : String(e)}); this process must restart`,
        });
      });
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

  /** Why the server refused the Resource for good, or null (see ResourceRefusal). */
  resourceRefusal(resource: ResourceId): ResourceRefusal | null {
    return this.#resources.get(toHex(resource))?.refusal ?? null;
  }

  /** Connects, and reconnects after losses (per the ReconnectPolicy) until stop(). */
  start(): void {
    if (this.#trapped) return;
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
        lastHeads: [],
        controlStale: false,
        missingEpochs: [],
        offered: null,
        snapshotPending: false,
        covered: [],
        unitsSinceSnapshot: 0,
        lastRound: "",
        refusal: null,
        refusedAttempt: 0,
        reopenAt: null,
        offering: new Set(),
        keysOffered: false,
        rehosted: false,
        recoveryTried: false,
        recoveryAttempts: 0,
        recoveryReopened: false,
      };
      this.#resources.set(key, ctx);
    }
    ctx.wanted = true;
    // An explicit open asks the server again after a refusal.
    ctx.refusal = null;
    ctx.refusedAttempt = 0;
    ctx.reopenAt = null;
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
          { kind: "host", genesis, resolve, reject },
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
    if (this.#connection.state === "READY") this.#expireRequests(now);
    this.#serial(async () => {
      for (const ctx of this.#resources.values()) {
        if (
          ctx.reopenAt !== null &&
          now >= ctx.reopenAt &&
          ctx.state === "CLOSED" &&
          ctx.wanted &&
          this.#connection.state === "READY"
        )
          await this.#sendOpen(ctx);
        // Periodic anti-entropy (§68.1), both planes: the server's answer
        // to CONTROL_HAVE also re-offers Control Records it still lacks,
        // e.g. after a refused or lost re-supply.
        if (ctx.state === "LIVE" && now - ctx.lastHave >= this.#antiEntropyMs) {
          this.#sendHave(ctx, now);
          this.#refreshControl(ctx);
        }
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
    const key = toHex(message.messageId);
    this.#requests.set(key, request);
    this.#sentAt.set(key, this.#o.now());
    this.#connection.send(message);
  }

  /**
   * Requests unanswered for requestTimeoutMs on a live connection (§70: a
   * lost request or reply): forgotten, and the step they belong to is
   * issued again while its Resource is still in that phase. A late reply
   * is harmless: units and records are idempotent.
   */
  #expireRequests(now: number): void {
    for (const key of this.#sentAt.keys()) if (!this.#requests.has(key)) this.#sentAt.delete(key);
    const resend = new Map<string, Request>();
    for (const [key, request] of this.#requests) {
      const sent = this.#sentAt.get(key);
      if (sent === undefined || now - sent < this.#requestTimeoutMs) continue;
      this.#requests.delete(key);
      this.#sentAt.delete(key);
      if (request.kind === "host") {
        request.reject(new Error("RESOURCE_HOST got no answer within the request timeout"));
        continue;
      }
      if (request.kind === "offer-data") {
        // Offered again on the next DATA_HAVE (§68.1).
        const ctx = this.#resources.get(request.resource);
        for (const u of request.units) ctx?.offering.delete(u.id);
        continue;
      }
      if (
        request.kind === "offer-control" ||
        request.kind === "offer-keys" ||
        request.kind === "recover-control"
      )
        continue;
      if ("resource" in request) resend.set(`${request.kind}:${request.resource}`, request);
    }
    for (const request of resend.values()) {
      if (!("resource" in request)) continue;
      const ctx = this.#resources.get(request.resource);
      if (ctx === undefined) continue;
      if (request.kind === "open" && ctx.state === "OPENING") {
        this.#move(ctx, "CLOSE");
        this.#serial(() => this.#sendOpen(ctx));
      } else if (request.kind === "rehost" && ctx.state === "CLOSED") {
        ctx.rehosted = false; // a lost answer: open again, which re-hosts again if needed
        this.#serial(() => this.#sendOpen(ctx));
      } else if (request.kind === "control" && ctx.state === "CONTROL_SYNC") {
        this.#serial(() => this.#controlRound(ctx, ctx.lastHeads));
      } else if (request.kind === "keys" && ctx.state === "KEY_SYNC") {
        this.#requestKeys(ctx, now);
      } else if (request.kind === "snapshot" && ctx.snapshotPending) {
        // A Snapshot is an optimization (§29.2): without it, replay the units.
        this.#error(
          "TIMEOUT",
          "the offered Snapshot did not arrive; replaying units instead",
          ctx.binding.resourceId,
        );
        this.#serial(() => this.#afterSnapshot(ctx));
      } else if (request.kind === "data-get" && ctx.state === "DATA_SYNC") {
        ctx.lastRound = ""; // a lost reply is not a round without progress
        ctx.expected = [];
        this.#serial(() => this.#dataRound(ctx));
      }
    }
  }

  #move(ctx: ResourceContext, event: ResourcePhaseEvent): boolean {
    const next = resourcePhaseTransition(ctx.state, event);
    if (next === undefined) return false;
    ctx.state = next;
    if (next === "LIVE") {
      ctx.refusedAttempt = 0;
      ctx.rehosted = false;
      ctx.recoveryTried = false;
      ctx.recoveryAttempts = 0;
    }
    this.#emit({ type: "resource-state", resourceId: ctx.binding.resourceId, state: next });
    if (next === "LIVE" && ctx.controlStale) {
      ctx.controlStale = false;
      this.#refreshControl(ctx);
    } else if (next === "CLOSED") ctx.controlStale = false; // reopening syncs Control anyway
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
    this.#maxMessageBytes = Number(ready.maxMessageBytes);
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
    this.#sentAt.clear();
    for (const ctx of this.#resources.values()) {
      this.#move(ctx, "CLOSE"); // §65, G-SM1: every Resource closes with the connection
      ctx.view = null;
      ctx.offering.clear();
      ctx.recoveryTried = false; // a new session may recover again (LFCP-02-106)
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
    ctx.reopenAt = null;
    ctx.keysOffered = false;
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
          await this.#markHosted(parseControlRecord(request.genesis).payload.resourceId);
          request.resolve(m.body.durability);
        } else if (request?.kind === "rehost") {
          this.#requests.delete(toHex(m.correlationId as Uint8Array));
          const ctx = this.#resources.get(request.resource);
          if (ctx === undefined) return;
          this.#emit({
            type: "rehost",
            resourceId: ctx.binding.resourceId,
            url: this.#o.url,
            outcome: "hosted",
          });
          if (ctx.wanted) await this.#sendOpen(ctx);
        }
        return;
      case "RESOURCE_OPENED": {
        const ctx = this.#ctx(m.body.resourceId);
        if (ctx === undefined || ctx.state !== "OPENING") return;
        this.#done(m);
        ctx.remoteHave = normalizeLiveHaves(m.body.haves);
        ctx.offered = m.body.snapshot ?? null;
        await this.#markHosted(ctx.binding.resourceId);
        if (ctx.recoveryReopened) {
          ctx.recoveryReopened = false;
          this.#recoveryEvent(ctx, "recovered");
        }
        this.#move(ctx, "OPENED");
        // §68.1, §88 step 6: what the server lacks goes first, Control Records before units.
        await this.#offerControl(ctx, m.body.heads);
        await this.#offerData(ctx);
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
        if (ctx?.snapshotPending) await this.#onSnapshot(ctx, m.body.snapshot);
        return;
      }
      case "DATA_HAVE": {
        const ctx = this.#ctx(m.body.resourceId);
        this.#done(m);
        if (ctx === undefined) return;
        ctx.remoteHave = normalizeLiveHaves(m.body.haves);
        await this.#offerData(ctx); // §68.1: both directions
        if (ctx.state === "LIVE") await this.#dataRound(ctx);
        return;
      }
      case "ACK":
        if (request?.kind === "recover-control") {
          this.#done(m);
          await this.#recoveryAccepted(request);
          return;
        }
        if (request !== undefined) {
          this.#done(m);
          if (request.kind === "offer-data")
            for (const u of request.units)
              this.#resources.get(request.resource)?.offering.delete(u.id);
          return;
        }
        await this.#onAck(m);
        return;
      case "NACK":
        if (request !== undefined) {
          this.#done(m);
          await this.#onRequestNack(request, m);
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

  async #onRequestNack(request: Request, m: LfcpMessage<"NACK">): Promise<void> {
    // The §62 name (e.g. AUTHORIZATION_FAILED), so applications can explain it; unknown codes keep their number.
    const code = NACK_NAME.get(m.body.code) ?? `NACK ${m.body.code}`;
    if (
      request.kind === "offer-control" ||
      request.kind === "offer-data" ||
      request.kind === "offer-keys"
    ) {
      this.#onOfferNack(request, code, m.body.diagnostic);
      return;
    }
    if (request.kind === "open" && code === "RESOURCE_NOT_HOSTED") {
      const ctx = this.#resources.get(request.resource);
      if (ctx !== undefined && (await this.#rehost(ctx))) return;
    }
    if (request.kind === "open" && code === "AUTHORIZATION_FAILED") {
      const ctx = this.#resources.get(request.resource);
      if (ctx?.recoveryReopened) {
        // The server holds our chain and still refuses: not a loss.
        ctx.recoveryReopened = false;
        this.#recoveryEvent(ctx, "ended", "still-refused");
      } else if (ctx !== undefined && (await this.#recoverAccess(ctx))) return;
    }
    if (request.kind === "recover-control") {
      await this.#recoveryRefused(request, code, m.body.details);
      return;
    }
    if (request.kind === "rehost") {
      const ctx = this.#resources.get(request.resource);
      if (ctx === undefined) return;
      this.#emit({
        type: "rehost",
        resourceId: ctx.binding.resourceId,
        url: this.#o.url,
        outcome: "refused",
        code,
      });
      this.#error(
        code,
        `re-hosting refused${m.body.diagnostic ? `: ${m.body.diagnostic}` : ""}`,
        ctx.binding.resourceId,
      );
      // §41.1: stop re-hosting on this route and tell the user; never retried by itself.
      this.#refuse(ctx, {
        code,
        url: this.#o.url,
        request: "rehost",
        ...(m.body.diagnostic === undefined ? {} : { diagnostic: m.body.diagnostic }),
      });
      return;
    }
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
      code,
      `${request.kind} refused${m.body.diagnostic ? `: ${m.body.diagnostic}` : ""}`,
      ctx?.binding.resourceId,
    );
    if (ctx === undefined || request.kind === "close") return;
    if (TERMINAL_RESOURCE_CODES.has(code)) {
      this.#refuse(ctx, {
        code,
        url: this.#o.url,
        request: request.kind,
        ...(m.body.diagnostic === undefined ? {} : { diagnostic: m.body.diagnostic }),
      });
      return;
    }
    if (request.kind === "keys") this.#keyBlocked(ctx);
    // A Snapshot is an optimization (§29.2): without it, replay the units.
    else if (request.kind === "snapshot") {
      if (ctx.snapshotPending) this.#serial(() => this.#afterSnapshot(ctx));
    }
    // A transient refusal of the open or of a sync round: the Resource
    // would otherwise sit there until the next reconnect. Start over after
    // a backoff. A refused DATA_HAVE is simply sent again (§69).
    else if (request.kind !== "data-have") this.#retryLater(ctx);
  }

  /** The server refused the Resource for good: CLOSED, not reopened until open() asks again. */
  #refuse(ctx: ResourceContext, refusal: ResourceRefusal): void {
    const subscribed = ctx.state !== "CLOSED" && ctx.state !== "OPENING";
    ctx.wanted = false;
    ctx.reopenAt = null;
    ctx.refusal = Object.freeze(refusal);
    // Stop any pushes the server may still send for it (§43).
    if (subscribed && this.#connection.state === "READY")
      this.#request(
        { kind: "close", resource: toHex(ctx.binding.resourceId) },
        createMessage("RESOURCE_CLOSE", { resourceId: ctx.binding.resourceId }),
      );
    this.#move(ctx, "CLOSE");
    this.#emit({ type: "resource-refused", resourceId: ctx.binding.resourceId, refusal });
  }

  /** CLOSED now, opened again after the ReconnectPolicy's delay for this Resource's attempt. */
  #retryLater(ctx: ResourceContext): void {
    if (ctx.state !== "CLOSED" && ctx.state !== "OPENING" && this.#connection.state === "READY")
      this.#request(
        { kind: "close", resource: toHex(ctx.binding.resourceId) },
        createMessage("RESOURCE_CLOSE", { resourceId: ctx.binding.resourceId }),
      );
    this.#move(ctx, "CLOSE");
    ctx.refusedAttempt += 1;
    const delay = (this.#o.reconnect ?? defaultReconnect)(ctx.refusedAttempt);
    ctx.reopenAt = delay === null ? null : this.#o.now() + delay;
  }

  // -------------------------------------------------------------------------
  // Control (§44-§47, §67)

  async #onControlHeads(ctx: ResourceContext, heads: readonly ControlHeadRef[]): Promise<void> {
    const chain = await loadControlChain(this.#o.storage, ctx.binding.resourceId);
    const local = chain?.kind === "linear" ? localControlOf(chain) : null;
    const plan = planControlSync(local, heads);
    if (plan.kind === "peer-behind") await this.#offerControl(ctx, heads); // §68.1
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
    ctx.lastHeads = heads;
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
    // DEKs we already hold for epochs the saved chain now has (our own
    // rotation, or a package that came before the row): no request needed.
    await adoptStoredDeks(this.#o.storage, this.#o.secrets, chain);
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
    if (ctx.view !== null) await adoptStoredDeks(this.#o.storage, this.#o.secrets, ctx.view);
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
          // §52: at most 256 epochs per request, the newest first: the
          // current epoch's DEK unblocks the Resource; older ones only let
          // their units apply, and a later round asks for them.
          epochs: missing.slice(-256),
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
      // Secret first, then the row that references it (LFCP-034). The
      // package itself is kept while we keep the Resource (§86), to
      // re-supply a server that lost it (§68.1).
      const ref = dekSecretRef(R, r.epoch);
      await this.#o.secrets.put(ref, exportSecretKeyBytes(r.dek));
      const parsed = parseKeyPackage(bytes);
      const writes: StorageWrite[] = [
        {
          op: "put-key-package",
          row: {
            packageId: hash32(parsed.signed.id),
            resourceId: R,
            dataEpoch: parsed.payload.dataEpoch,
            recipient: parsed.payload.recipient,
            sender: parsed.payload.sender,
            bytes: parsed.signed.bytes,
          },
        },
      ];
      const row = (await this.#o.storage.control.epochs(R)).find((e) => e.epoch === r.epoch);
      if (row !== undefined) {
        const next: EpochRow = { ...row, dekRef: ref };
        writes.push({ op: "put-epoch", resourceId: R, epoch: next });
      }
      await this.#o.storage.commit(writes);
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
      const R = ctx.binding.resourceId;
      // Snapshots that crashed the engine twice are never loaded again.
      for (const item of await this.#snapshots.recover(R))
        this.#error(
          "INVALID_AUTOMERGE_BYTES",
          `Snapshot ${item.slice("snapshot:".length)} crashed the profile engine twice; it is not loaded again on this device`,
          R,
        );
      const r = await ctx.binding.applier.replayStored(ctx.view);
      if (r.replayed.length > 0 || r.skipped.length > 0 || r.crashed.length > 0) {
        ctx.binding.checkpointer?.noteChange();
        this.#emit({ type: "replayed", resourceId: R, ...r });
      }
      for (const unitId of r.crashed)
        this.#error(
          "INVALID_AUTOMERGE_BYTES",
          `Data Unit ${toHex(unitId)} crashed the profile engine twice; it is quarantined on this device`,
          R,
        );
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
    const R = ctx.binding.resourceId;
    await this.#snapshots.recover(R);
    if (this.#snapshots.suspicion(R, snapshotItem(offered.snapshotId)) === 2) return false;
    const local = (await resourceSyncState(this.#o.storage, ctx.binding.resourceId)).have;
    return missingFrom(local, normalizeLiveHaves(offered.frontier)).length > 0;
  }

  async #onSnapshot(ctx: ResourceContext, bytes: Uint8Array): Promise<void> {
    const R = ctx.binding.resourceId;
    const view = ctx.view;
    const binding = ctx.binding.snapshot;
    if (view !== null && binding !== undefined) {
      // Decode and load under the crash-loop breaker; a trap in decode is
      // rethrown, not reported as the Snapshot's local failure.
      let trap: unknown;
      const codec = binding.codec;
      const guarded = {
        dataProfile: codec.dataProfile,
        encode: (v: unknown) => codec.encode(v as never),
        decode: (plaintext: Uint8Array) => {
          try {
            return codec.decode(plaintext);
          } catch (e) {
            if (isEngineTrap(e)) trap = e;
            throw e;
          }
        },
      };
      const r = await this.#snapshots.run(R, [snapshotItem(sha256(bytes))], async () => {
        const received = await receiveSnapshot(view, bytes, {
          dek: dekResolver(this.#o.storage, this.#o.secrets, R),
          profile: guarded,
        });
        if (trap !== undefined) throw trap;
        if (received.kind === "accepted") binding.load(received.value);
        return received;
      });
      if (r.kind === "accepted") {
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
    // Ranges stay intervals: the work is bounded by their number, never by
    // their span (a Have may announce up to 2^64 - 1 sequences).
    let expected: HaveVector = [];
    for (const r of missing) expected = addRange(expected, r.actor, r.start, r.end);
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
    // Units a loaded Snapshot covers are accepted as covered, one by one;
    // runs of the others go to the applier together (receiveBatch), so the
    // profile merges a catch-up at once.
    const outcomes: ApplyOutcome[] = [];
    let run: Uint8Array[] = [];
    const flushRun = async () => {
      if (run.length > 0) outcomes.push(...(await ctx.binding.applier.receiveBatch(view, run)));
      run = [];
    };
    for (const bytes of units) {
      let covered = false;
      try {
        const p = parseDataUnit(bytes).payload;
        ctx.received = addSequence(ctx.received, p.actor, p.actorSeq);
        covered = hasSequence(ctx.covered, p.actor, p.actorSeq);
      } catch {
        // malformed: the applier reports it
      }
      if (!covered) {
        run.push(bytes);
        continue;
      }
      await flushRun();
      outcomes.push(await ctx.binding.applier.acceptCovered(view, bytes));
    }
    await flushRun();
    for (const outcome of outcomes) {
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
        else ctx.controlStale = true;
  }

  async #onNack(m: LfcpMessage<"NACK">): Promise<void> {
    const outcome = await this.#o.outbound.onNack(m, iso(this.#o.now()));
    this.#emit({ type: "nack", outcome });
    if (outcome.kind === "needs-control-sync")
      for (const ctx of this.#resources.values())
        if (ctx.state === "LIVE") this.#refreshControl(ctx);
    // §51.1: the server lost what our unit names. Its DATA_HAVE answer
    // starts the offer (§68.1), which releases the held items.
    if (outcome.kind === "needs-offer") {
      const ctx = this.#ctx(outcome.resourceId);
      if (ctx !== undefined && (ctx.state === "LIVE" || ctx.state === "DATA_SYNC"))
        this.#sendHave(ctx, this.#o.now());
    }
  }

  // -------------------------------------------------------------------------
  // Offering what the server lacks (§68.1) and re-hosting (§41.1)

  async #markHosted(resource: ResourceId): Promise<void> {
    const key = hostedMark(resource, this.#o.url);
    if ((await this.#o.storage.localMarks.get(key)) !== undefined) return;
    await this.#o.storage.commit([{ op: "put-local-mark", key, value: "1" }]);
  }

  /**
   * §41.1: RESOURCE_NOT_HOSTED from a route in the Resource's route set that
   * hosted or opened it for us before: host it again from the exact Genesis
   * bytes, then open it. False when re-hosting is not allowed here.
   */
  async #rehost(ctx: ResourceContext): Promise<boolean> {
    if (ctx.rehosted || this.#connection.state !== "READY") return false;
    const R = ctx.binding.resourceId;
    const chain = await loadControlChain(this.#o.storage, R);
    if (chain?.kind !== "linear") return false;
    const route = chain.state.route;
    const url = this.#o.url;
    if (!route.endpoints.some((e) => e.url === url) && route.coordinatorUrl !== url) return false;
    if ((await this.#o.storage.localMarks.get(hostedMark(R, url))) === undefined) return false;
    const genesis = chain.records[0];
    if (genesis === undefined || genesis.payload.controlSeq !== 0n) return false;
    ctx.rehosted = true;
    this.#move(ctx, "CLOSE");
    this.#request(
      { kind: "rehost", resource: toHex(R) },
      createMessage("RESOURCE_HOST", { genesis: genesis.signed.bytes }),
    );
    return true;
  }

  /**
   * LFCP-02-106: RESOURCE_OPEN was refused with AUTHORIZATION_FAILED. When
   * our validated chain grants us data/read, the server may have lost the
   * records that do (a restore): push our head, and follow the server's
   * answer (see access-recovery.ts). False when no recovery runs; the
   * refusal then stands as before.
   */
  async #recoverAccess(ctx: ResourceContext): Promise<boolean> {
    if (ctx.recoveryTried || this.#connection.state !== "READY") return false;
    const chain = await loadControlChain(this.#o.storage, ctx.binding.resourceId);
    if (chain?.kind !== "linear") return false;
    const step = startRecovery(chain.state, chain.records, this.#o.signer.descriptor.principalId);
    ctx.recoveryTried = true;
    if (step.kind !== "push") {
      this.#recoveryEvent(ctx, "ended", step.kind === "final" ? step.reason : undefined);
      return false;
    }
    this.#recoveryEvent(ctx, "started");
    this.#move(ctx, "CLOSE");
    await this.#recoveryStep(ctx, step);
    return true;
  }

  async #recoveryStep(ctx: ResourceContext, step: RecoveryStep): Promise<void> {
    const R = ctx.binding.resourceId;
    if (step.kind === "reopen") {
      ctx.recoveryReopened = true;
      if (ctx.wanted) await this.#sendOpen(ctx);
      return;
    }
    if (step.kind === "final") {
      this.#recoveryEvent(ctx, "ended", step.reason);
      this.#refuse(ctx, { code: "AUTHORIZATION_FAILED", url: this.#o.url, request: "open" });
      return;
    }
    if (this.#connection.state !== "READY") return; // the next session opens and may recover again
    const chain = await loadControlChain(this.#o.storage, R);
    const record = chain?.kind === "linear" ? chain.records[step.index] : undefined;
    const previous = record?.payload.prevControlId ?? null;
    if (record === undefined || previous === null) {
      await this.#recoveryStep(ctx, { kind: "final", reason: "refused" });
      return;
    }
    this.#request(
      { kind: "recover-control", resource: toHex(R), index: step.index },
      createMessage("CONTROL_PUT", {
        resourceId: R,
        expectedHead: previous,
        record: record.signed.bytes,
      }),
    );
  }

  async #recoveryAccepted(request: Extract<Request, { kind: "recover-control" }>): Promise<void> {
    const ctx = this.#resources.get(request.resource);
    if (ctx === undefined) return;
    const chain = await loadControlChain(this.#o.storage, ctx.binding.resourceId);
    if (chain?.kind !== "linear") return;
    await this.#recoveryStep(ctx, afterAccepted(chain.records, request.index));
  }

  async #recoveryRefused(
    request: Extract<Request, { kind: "recover-control" }>,
    code: string,
    details: unknown,
  ): Promise<void> {
    const ctx = this.#resources.get(request.resource);
    if (ctx === undefined) return;
    if (RECOVERY_TRANSIENT_CODES.has(code) && ctx.recoveryAttempts < RECOVERY_TRANSIENT_ATTEMPTS) {
      // Open again after a backoff; the refused open recovers again.
      ctx.recoveryAttempts += 1;
      ctx.recoveryTried = false;
      this.#retryLater(ctx);
      return;
    }
    const chain = await loadControlChain(this.#o.storage, ctx.binding.resourceId);
    const step: RecoveryStep =
      code === "CONTROL_HEAD_MISMATCH" && chain?.kind === "linear"
        ? afterMismatch(chain.records, details)
        : { kind: "final", reason: "refused" };
    await this.#recoveryStep(ctx, step);
  }

  #recoveryEvent(
    ctx: ResourceContext,
    outcome: "started" | "recovered" | "ended",
    reason?: string,
  ): void {
    this.#emit({
      type: "access-recovery",
      resourceId: ctx.binding.resourceId,
      url: this.#o.url,
      outcome,
      ...(reason === undefined ? {} : { reason }),
    });
  }

  /**
   * §68.1: the server's Control Head is a record we hold below our own head:
   * upload the records above it, one CONTROL_PUT each, in order, each
   * expecting the record before it.
   */
  async #offerControl(ctx: ResourceContext, heads: readonly ControlHeadRef[]): Promise<void> {
    if (this.#connection.state !== "READY") return;
    const R = ctx.binding.resourceId;
    const chain = await loadControlChain(this.#o.storage, R);
    if (chain?.kind !== "linear") return;
    const plan = planControlSync(localControlOf(chain), heads);
    if (plan.kind !== "peer-behind") return;
    for (const record of chain.records) {
      if (record.payload.controlSeq <= plan.peerSeq) continue;
      const previous = record.payload.prevControlId;
      if (previous === null) continue;
      this.#request(
        { kind: "offer-control", resource: toHex(R) },
        createMessage("CONTROL_PUT", {
          resourceId: R,
          expectedHead: previous,
          record: record.signed.bytes,
        }),
      );
    }
    await this.#offerKeys(ctx);
  }

  /**
   * §68.1: the accepted units the server's Have Vector lacks, ours and
   * other actors' (relay), per actor in ascending sequence. Units still in
   * our outbound queue go through it instead. Then the queued items held
   * for UNKNOWN_PREVIOUS are released behind them.
   */
  async #offerData(ctx: ResourceContext): Promise<void> {
    if (this.#connection.state !== "READY") return;
    const R = ctx.binding.resourceId;
    const queued = new Set((await this.#o.storage.outbound.list(R)).map((o) => toHex(o.itemId)));
    let local: HaveVector = [];
    for (const status of OFFERABLE)
      for (const u of await this.#o.storage.dataUnits.withStatus(R, status))
        if (u.accepted) local = addSequence(local, u.actor, u.actorSeq);
    const { offer } = haveDifference(local, ctx.remoteHave);
    const offerable: ReadonlySet<string> = new Set(OFFERABLE);
    let sent = 0;
    for (const range of offer) {
      const units = (
        await this.#o.storage.dataUnits.range(
          R,
          range.actor,
          actorSequence(range.start),
          actorSequence(range.end),
        )
      ).filter(
        (u: StoredDataUnit) =>
          u.accepted &&
          offerable.has(u.status) &&
          !queued.has(toHex(u.unitId)) &&
          !ctx.offering.has(toHex(u.unitId)),
      );
      sent += units.length;
      this.#offerUnits(
        ctx,
        units.map((u) => ({ id: toHex(u.unitId), bytes: u.bytes })),
      );
    }
    await this.#o.outbound.offered(R);
    if (sent > 0) await this.#offerKeys(ctx);
    await this.#flush(ctx);
  }

  /** DATA_PUTs of one actor's units in order, within the message size and object limits. */
  #offerUnits(
    ctx: ResourceContext,
    units: readonly { readonly id: string; readonly bytes: Uint8Array }[],
  ): void {
    const R = ctx.binding.resourceId;
    const limit = this.#maxMessageBytes - 1024;
    let batch: { id: string; bytes: Uint8Array }[] = [];
    let size = 0;
    const send = () => {
      if (batch.length === 0) return;
      for (const u of batch) ctx.offering.add(u.id);
      this.#request(
        { kind: "offer-data", resource: toHex(R), units: batch },
        createMessage("DATA_PUT", { resourceId: R, objects: batch.map((u) => u.bytes) }),
      );
      batch = [];
      size = 0;
    };
    for (const u of units) {
      if (batch.length >= OFFER_BATCH || size + u.bytes.length > limit) send();
      batch.push(u);
      size += u.bytes.length;
    }
    send();
  }

  /**
   * §68.1, §86: a server that lacked Control Records or units may have lost
   * Key Packages too: the ones we sent or that are addressed to us are
   * uploaded again, once per open. A package the server stores is answered
   * as the first time (§70).
   */
  async #offerKeys(ctx: ResourceContext): Promise<void> {
    if (ctx.keysOffered || this.#connection.state !== "READY") return;
    ctx.keysOffered = true;
    const R = ctx.binding.resourceId;
    const me = toHex(this.#o.signer.descriptor.principalId);
    const packages = (await this.#o.storage.keyPackages.list(R)).filter(
      (k) => toHex(k.sender) === me || toHex(k.recipient) === me,
    );
    const limit = this.#maxMessageBytes - 1024;
    for (let i = 0; i < packages.length; ) {
      const batch: Uint8Array[] = [];
      let size = 0;
      while (i < packages.length && batch.length < OFFER_BATCH) {
        const bytes = (packages[i] as { bytes: Uint8Array }).bytes;
        if (batch.length > 0 && size + bytes.length > limit) break;
        batch.push(bytes);
        size += bytes.length;
        i++;
      }
      this.#request(
        { kind: "offer-keys", resource: toHex(R) },
        createMessage("KEY_PACKAGE_PUT", { resourceId: R, objects: batch }),
      );
    }
  }

  /**
   * A refused offer. A DATA_PUT is all-or-nothing (§51): each unit of a
   * refused batch is offered again alone. ACTOR_EQUIVOCATION for a relayed
   * unit is expected when the server holds the other unit of a pair, and
   * UNKNOWN_PREVIOUS when it lacks an earlier unit we do not hold either:
   * neither is an alarm. A refused Control Record (the server's head moved)
   * is caught up by the next Control round.
   */
  #onOfferNack(
    request: Extract<Request, { kind: "offer-control" | "offer-data" | "offer-keys" }>,
    code: string,
    diagnostic: string | undefined,
  ): void {
    const ctx = this.#resources.get(request.resource);
    if (ctx === undefined) return;
    if (request.kind === "offer-data") {
      for (const u of request.units) ctx.offering.delete(u.id);
      if (request.units.length > 1) {
        for (const u of request.units) this.#offerUnits(ctx, [u]);
        return;
      }
      if (code === "ACTOR_EQUIVOCATION" || code === "UNKNOWN_PREVIOUS") return;
    }
    if (request.kind === "offer-control" && code === "CONTROL_HEAD_MISMATCH") return;
    this.#error(
      code,
      `an object offered to the server was refused (§68.1)${diagnostic ? `: ${diagnostic}` : ""}`,
      ctx.binding.resourceId,
    );
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
