import {
  type ControlRecordId,
  controlRecordId,
  type DataEpoch,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type AnyMessage,
  type ControlHeadRef,
  createMessage,
  type DataRange,
  ERROR_CODE,
  type LiveActorHave,
  type Signer,
} from "@openlfcp/wire";
import {
  ConnectionNotReady,
  LfcpConnection,
  type UpgradeProbe,
  type UpgradeRefusal,
  type WebSocketFactory,
} from "../connection.js";

/**
 * The network port of the identity flows (IDENTITY-PROFILE-01 §§5–9).
 *
 * Every flow talks to coordinators through an IdentityChannel: one
 * authenticated session as one Principal (the installation's own, a
 * pairing device's, an Invitation Principal's) to one coordinator. The
 * port keeps the flows independent of the transport: connectionNetwork()
 * runs it over LfcpConnection, tests run it against an in-memory
 * coordinator. A transport failure throws IdentityUnavailable and leaves
 * every journal as it is, so the flow resumes later (§9); a NACK is an
 * answer, returned to the flow.
 */

/** The coordinator's answer to an upload (CONTROL_PUT, KEY_PACKAGE_PUT, DATA_PUT, RESOURCE_HOST). */
export type IdentityAnswer =
  | { readonly kind: "ack" }
  | {
      readonly kind: "nack";
      readonly code: string;
      /** For CONTROL_HEAD_MISMATCH: the coordinator's head, when it named one (§47). */
      readonly head?: ControlRecordId;
    };

export type OpenAnswer =
  | {
      readonly kind: "opened";
      readonly heads: readonly ControlHeadRef[];
      readonly haves: readonly LiveActorHave[];
    }
  | { readonly kind: "nack"; readonly code: string };

export interface IdentityChannel {
  /** READY's extensions (§37); `identity-01` when the server supports device records. */
  readonly extensions: readonly string[];
  /** RESOURCE_HOST with the exact Genesis bytes (§39). */
  host(genesis: Uint8Array): Promise<IdentityAnswer>;
  /** RESOURCE_OPEN without subscriptions (§41). */
  open(resource: ResourceId): Promise<OpenAnswer>;
  /** CONTROL_GET from `start` to the end (§45); throws IdentityRefused on a NACK. */
  control(resource: ResourceId, start: bigint): Promise<readonly Uint8Array[]>;
  /** CONTROL_PUT with compare-and-swap (§47). */
  putControl(
    resource: ResourceId,
    expectedHead: ControlRecordId,
    record: Uint8Array,
  ): Promise<IdentityAnswer>;
  /** KEY_PACKAGE_GET (§52: at most 256 epochs); throws IdentityRefused on a NACK. */
  keyPackages(
    resource: ResourceId,
    recipient: PrincipalId,
    epochs: readonly DataEpoch[],
  ): Promise<readonly Uint8Array[]>;
  /** KEY_PACKAGE_PUT (§53). */
  putKeyPackage(resource: ResourceId, bytes: Uint8Array): Promise<IdentityAnswer>;
  /** DATA_GET of the ranges (§49); throws IdentityRefused on a NACK. */
  dataUnits(resource: ResourceId, ranges: readonly DataRange[]): Promise<readonly Uint8Array[]>;
  /** DATA_PUT of one unit (§50). */
  putDataUnit(resource: ResourceId, bytes: Uint8Array): Promise<IdentityAnswer>;
  close(): void;
}

export interface IdentityNetwork {
  /** An authenticated session as `signer` to the coordinator at `url`; throws IdentityUnavailable. */
  connect(signer: Signer, url: string): Promise<IdentityChannel>;
  /**
   * Closes the sessions a network keeps for reuse (connectionNetwork's
   * keepAliveMs), also ones a flow still uses (its requests become
   * unavailable): call it when the application is done, so that no open
   * WebSocket keeps the process alive. A later call opens a new session.
   */
  close?(): void;
}

/** The coordinator could not be reached or the session ended: a timeout is never a decision (§6). */
export class IdentityUnavailable extends Error {
  /**
   * `"rate-limited"`: the coordinator refused the WebSocket upgrade with HTTP
   * 429 (its new-connections-per-address limit, decision I18), as the
   * network's `upgradeProbe` learned; undefined for any other cause, or
   * without a probe (a browser's WebSocket does not tell).
   */
  readonly reason: "rate-limited" | undefined;
  /** The server's Retry-After, in milliseconds, when it sent one. */
  readonly retryAfterMs: number | undefined;

  constructor(message: string, refusal?: UpgradeRefusal) {
    // The connection's reason already says "rate limited (HTTP 429, …)".
    super(message);
    this.name = "IdentityUnavailable";
    this.reason = refusal === undefined ? undefined : "rate-limited";
    this.retryAfterMs = refusal?.retryAfterMs;
  }
}

/** A read the coordinator refused (NACK), e.g. AUTHORIZATION_FAILED for a revoked device (§8.6). */
export class IdentityRefused extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "IdentityRefused";
  }
}

/** The READY extension of servers that support device records (W §37). */
export const IDENTITY_EXTENSION = "identity-01";

/** Connections reused within one flow run, by (Principal, URL); closed together. */
export class ChannelPool {
  readonly #network: IdentityNetwork;
  readonly #open = new Map<string, Promise<IdentityChannel>>();

  constructor(network: IdentityNetwork) {
    this.#network = network;
  }

  get(signer: Signer, url: string): Promise<IdentityChannel> {
    const key = `${toHex(signer.descriptor.principalId)} ${url}`;
    let c = this.#open.get(key);
    if (c === undefined) {
      c = this.#network.connect(signer, url);
      // A failed connection is not reused.
      c.catch(() => this.#open.delete(key));
      this.#open.set(key, c);
    }
    return c;
  }

  closeAll(): void {
    for (const c of this.#open.values()) c.then((ch) => ch.close()).catch(() => undefined);
    this.#open.clear();
  }
}

const CODE_NAME = new Map<bigint, string>(Object.entries(ERROR_CODE).map(([k, v]) => [v, k]));
const codeName = (code: bigint): string => CODE_NAME.get(code) ?? `ERROR_${code}`;
const MAX_EPOCHS_PER_GET = 256;

/** Request/response over one LfcpConnection. */
class RequestSession implements IdentityChannel {
  readonly #connection: LfcpConnection;
  readonly #inbox: AnyMessage[] = [];
  /** The message IDs of the requests waiting for replies: anything else is dropped. */
  readonly #pending = new Set<string>();
  #waiters: (() => void)[] = [];
  #closed: string | null = null;
  #refusal: UpgradeRefusal | undefined;
  #extensions: readonly string[] | null = null;
  readonly #timeout: (() => Promise<unknown>) | undefined;

  constructor(options: {
    url: string;
    signer: Signer;
    now: () => number;
    webSocket?: WebSocketFactory;
    upgradeProbe?: UpgradeProbe;
    timeout?: () => Promise<unknown>;
  }) {
    this.#timeout = options.timeout;
    this.#connection = new LfcpConnection(
      {
        url: options.url,
        signer: options.signer,
        now: options.now,
        ...(options.webSocket === undefined ? {} : { webSocket: options.webSocket }),
        ...(options.upgradeProbe === undefined ? {} : { upgradeProbe: options.upgradeProbe }),
      },
      {
        state: () => undefined,
        ready: (r) => {
          this.#extensions = Object.freeze([...r.extensions]);
          this.#wake();
        },
        message: (m) => {
          // A reply to a request of ours; a push (an accepted record of a Resource this
          // session opened, §69) or a stale reply is not kept: a reused session would
          // otherwise hold every push it ever got.
          if (m.correlationId === undefined || !this.#pending.has(toHex(m.correlationId))) return;
          this.#inbox.push(m);
          this.#wake();
        },
        closed: (reason, refusal) => {
          this.#closed = reason;
          this.#refusal = refusal;
          this.#wake();
        },
      },
    );
  }

  get extensions(): readonly string[] {
    return this.#extensions ?? [];
  }

  /** The connection closed (the server, the network, or close()): it is not used again. */
  get closed(): boolean {
    return this.#closed !== null;
  }

  /** The §38 heartbeat of an idle session kept for reuse; false when it is dead. */
  tick(now: number): boolean {
    return this.#connection.tick(now);
  }

  #wake(): void {
    const waiting = this.#waiters;
    this.#waiters = [];
    for (const w of waiting) w();
  }

  async #until<T>(take: () => T | undefined, what: string): Promise<T> {
    let timedOut = false;
    this.#timeout?.().then(
      () => {
        timedOut = true;
        this.#wake();
      },
      () => undefined,
    );
    for (;;) {
      const v = take();
      if (v !== undefined) return v;
      if (this.#closed !== null)
        throw new IdentityUnavailable(
          `the connection closed while waiting for ${what}: ${this.#closed}`,
          this.#refusal,
        );
      if (timedOut) throw new IdentityUnavailable(`timed out waiting for ${what}`);
      await new Promise<void>((resolve) => this.#waiters.push(resolve));
    }
  }

  async connect(): Promise<void> {
    this.#connection.connect();
    await this.#until(() => (this.#extensions !== null ? true : undefined), "READY");
  }

  /** Sends a request and returns its correlated replies, until `done` says the last one arrived. */
  async #request(
    m: AnyMessage,
    what: string,
    done: (reply: AnyMessage) => boolean = () => true,
  ): Promise<AnyMessage[]> {
    const id = toHex(m.messageId);
    this.#pending.add(id);
    try {
      try {
        this.#connection.send(m);
      } catch (e) {
        // Closed between two requests (a reused session the server dropped): unavailable, retried.
        if (e instanceof ConnectionNotReady)
          throw new IdentityUnavailable(`the connection closed before ${what} was asked`);
        throw e;
      }
      const replies: AnyMessage[] = [];
      for (;;) {
        const reply = await this.#until(() => {
          const i = this.#inbox.findIndex(
            (r) => r.correlationId !== undefined && toHex(r.correlationId) === id,
          );
          return i === -1 ? undefined : this.#inbox.splice(i, 1)[0];
        }, what);
        replies.push(reply);
        if (reply.type === "NACK" || done(reply)) return replies;
      }
    } finally {
      this.#pending.delete(id);
      // Replies that came after the last one awaited (none should) are dropped with it.
      for (let i = this.#inbox.length - 1; i >= 0; i--) {
        const c = this.#inbox[i]?.correlationId;
        if (c !== undefined && toHex(c) === id) this.#inbox.splice(i, 1);
      }
    }
  }

  #answer(reply: AnyMessage | undefined): IdentityAnswer {
    if (reply?.type === "ACK" || reply?.type === "RESOURCE_HOSTED") return { kind: "ack" };
    if (reply?.type === "NACK") {
      const head = reply.body.details;
      return Object.freeze({
        kind: "nack",
        code: codeName(reply.body.code),
        ...(head instanceof Uint8Array && head.length === 32
          ? { head: controlRecordId(head) }
          : {}),
      });
    }
    throw new IdentityUnavailable(`unexpected answer ${reply?.type ?? "none"}`);
  }

  #refuse(reply: AnyMessage, what: string): never {
    if (reply.type === "NACK")
      throw new IdentityRefused(codeName(reply.body.code), `${what} was refused`);
    throw new IdentityUnavailable(`${what} was answered with ${reply.type}`);
  }

  async host(genesis: Uint8Array): Promise<IdentityAnswer> {
    const [reply] = await this.#request(
      createMessage("RESOURCE_HOST", { genesis }),
      "RESOURCE_HOSTED",
    );
    return this.#answer(reply);
  }

  async open(resource: ResourceId): Promise<OpenAnswer> {
    const [reply] = await this.#request(
      createMessage("RESOURCE_OPEN", { resourceId: resource, heads: [], haves: [] }),
      "RESOURCE_OPENED",
    );
    if (reply?.type === "RESOURCE_OPENED")
      return Object.freeze({ kind: "opened", heads: reply.body.heads, haves: reply.body.haves });
    if (reply?.type === "NACK") return { kind: "nack", code: codeName(reply.body.code) };
    throw new IdentityUnavailable(`RESOURCE_OPEN was answered with ${reply?.type}`);
  }

  async control(resource: ResourceId, start: bigint): Promise<readonly Uint8Array[]> {
    const opened = await this.open(resource);
    if (opened.kind === "nack") throw new IdentityRefused(opened.code, "RESOURCE_OPEN was refused");
    const end = opened.heads.reduce((m, h) => (h.seq > m ? h.seq : m), -1n);
    if (end < start) return [];
    const out: Uint8Array[] = [];
    const replies = await this.#request(
      createMessage("CONTROL_GET", { resourceId: resource, start, end }),
      "CONTROL_BATCH",
      (r) => {
        if (r.type === "CONTROL_BATCH") out.push(...r.body.objects);
        return out.length >= Number(end - start + 1n);
      },
    );
    const last = replies.at(-1) as AnyMessage;
    if (last.type === "NACK") this.#refuse(last, "CONTROL_GET");
    return out;
  }

  async putControl(
    resource: ResourceId,
    expectedHead: ControlRecordId,
    record: Uint8Array,
  ): Promise<IdentityAnswer> {
    const [reply] = await this.#request(
      createMessage("CONTROL_PUT", { resourceId: resource, expectedHead, record }),
      "the CONTROL_PUT answer",
    );
    return this.#answer(reply);
  }

  async keyPackages(
    resource: ResourceId,
    recipient: PrincipalId,
    epochs: readonly DataEpoch[],
  ): Promise<readonly Uint8Array[]> {
    const out: Uint8Array[] = [];
    for (let i = 0; i < epochs.length; i += MAX_EPOCHS_PER_GET) {
      const [reply] = await this.#request(
        createMessage("KEY_PACKAGE_GET", {
          resourceId: resource,
          recipient,
          epochs: epochs.slice(i, i + MAX_EPOCHS_PER_GET),
        }),
        "KEY_PACKAGE_BATCH",
      );
      if (reply?.type !== "KEY_PACKAGE_BATCH") this.#refuse(reply as AnyMessage, "KEY_PACKAGE_GET");
      out.push(...reply.body.objects);
    }
    return out;
  }

  async putKeyPackage(resource: ResourceId, bytes: Uint8Array): Promise<IdentityAnswer> {
    const [reply] = await this.#request(
      createMessage("KEY_PACKAGE_PUT", { resourceId: resource, objects: [bytes] }),
      "the KEY_PACKAGE_PUT answer",
    );
    return this.#answer(reply);
  }

  async dataUnits(
    resource: ResourceId,
    ranges: readonly DataRange[],
  ): Promise<readonly Uint8Array[]> {
    if (ranges.length === 0) return [];
    const want = ranges.reduce((n, r) => n + Number(r.end - r.start + 1n), 0);
    const out: Uint8Array[] = [];
    const replies = await this.#request(
      createMessage("DATA_GET", { resourceId: resource, ranges }),
      "DATA_BATCH",
      (r) => {
        if (r.type === "DATA_BATCH") out.push(...r.body.objects);
        // A server may hold fewer units than asked; an empty batch ends the answer.
        return out.length >= want || (r.type === "DATA_BATCH" && r.body.objects.length === 0);
      },
    );
    const last = replies.at(-1) as AnyMessage;
    if (last.type === "NACK") this.#refuse(last, "DATA_GET");
    return out;
  }

  async putDataUnit(resource: ResourceId, bytes: Uint8Array): Promise<IdentityAnswer> {
    const [reply] = await this.#request(
      createMessage("DATA_PUT", { resourceId: resource, objects: [bytes] }),
      "the DATA_PUT answer",
    );
    return this.#answer(reply);
  }

  close(): void {
    this.#connection.close("the identity flow finished");
  }
}

export interface ConnectionNetworkOptions {
  readonly now: () => number;
  readonly webSocket?: WebSocketFactory;
  /**
   * A fresh timer per awaited reply (e.g. `() => sleep(30_000)` from the
   * host): when it resolves first the request is "unavailable", never a
   * decision (§6). Without it a request waits until the connection closes.
   */
  readonly timeout?: () => Promise<unknown>;
  /**
   * Reuse a session per (Principal, coordinator) across flow calls (decision
   * I18: the server admits 20 new WebSockets per minute and address): a
   * session no flow uses any more stays open this long, kept alive by the
   * §38 heartbeat, for the next call. 0 (the default) closes it when its
   * flow ends, as before. A session the server closed is never reused.
   */
  readonly keepAliveMs?: number;
  /** Learns why an upgrade failed (e.g. HTTP 429), where the platform WebSocket does not say. */
  readonly upgradeProbe?: UpgradeProbe;
  /** Timers of the kept sessions (default: the global ones, unref'ed where the runtime has it). */
  readonly timers?: {
    readonly setTimeout: (fn: () => void, ms: number) => unknown;
    readonly clearTimeout: (handle: unknown) => void;
  };
}

/** How often a kept session's heartbeat runs (the server's interval is READY's, ≥ 1 s). */
const KEPT_TICK_MS = 1000;

/** The runtime's timers (every supported platform has them), unref'ed where it can be. */
const globalTimers = {
  setTimeout: (fn: () => void, ms: number): unknown => {
    const g = globalThis as unknown as {
      setTimeout: (fn: () => void, ms: number) => { unref?: () => void };
    };
    const h = g.setTimeout(fn, ms);
    h.unref?.();
    return h;
  },
  clearTimeout: (h: unknown): void => {
    (globalThis as unknown as { clearTimeout: (h: unknown) => void }).clearTimeout(h);
  },
};

/** A session kept for reuse: its users, and the timer that closes it once idle. */
interface Kept {
  readonly session: Promise<RequestSession>;
  users: number;
  idleSince: number | null;
  timer: unknown;
}

/**
 * The identity network over LfcpConnection: one session per (Principal,
 * coordinator) and flow call, or, with `keepAliveMs`, one per (Principal,
 * coordinator) shared by every call while it is in use or recently was.
 * A shared session carries concurrent requests: replies are matched by
 * correlation ID.
 */
export function connectionNetwork(options: ConnectionNetworkOptions): IdentityNetwork {
  const open = (signer: Signer, url: string) =>
    new RequestSession({
      url,
      signer,
      now: options.now,
      ...(options.timeout === undefined ? {} : { timeout: options.timeout }),
      ...(options.webSocket === undefined ? {} : { webSocket: options.webSocket }),
      ...(options.upgradeProbe === undefined ? {} : { upgradeProbe: options.upgradeProbe }),
    });
  const connected = async (s: RequestSession) => {
    try {
      await s.connect();
    } catch (e) {
      s.close();
      throw e;
    }
    return s;
  };
  const keepAlive = options.keepAliveMs ?? 0;
  if (keepAlive <= 0)
    return { connect: (signer, url) => connected(open(signer, url)), close: () => undefined };

  const timers = options.timers ?? globalTimers;
  const kept = new Map<string, Kept>();
  const forget = (key: string, k: Kept) => {
    if (kept.get(key) === k) kept.delete(key);
    timers.clearTimeout(k.timer);
  };
  /** While idle: the heartbeat, and the close once idle for keepAliveMs. */
  const watch = (key: string, k: Kept, s: RequestSession) => {
    k.timer = timers.setTimeout(() => {
      if (k.users > 0 || k.idleSince === null) return;
      const now = options.now();
      // Expired first: a PING sent right before the close would be answered after it.
      if (s.closed || now - k.idleSince >= keepAlive || !s.tick(now)) {
        forget(key, k);
        s.close();
        return;
      }
      watch(key, k, s);
    }, KEPT_TICK_MS);
  };
  return {
    close() {
      for (const [key, k] of [...kept]) {
        forget(key, k);
        k.session.then((s) => s.close()).catch(() => undefined);
      }
    },
    async connect(signer, url) {
      const key = `${toHex(signer.descriptor.principalId)} ${url}`;
      let k = kept.get(key);
      if (k !== undefined) {
        const s = await k.session.catch(() => undefined);
        if (s === undefined || s.closed) {
          forget(key, k);
          k = undefined;
        }
      }
      if (k === undefined) {
        const session = connected(open(signer, url));
        const fresh: Kept = { session, users: 0, idleSince: null, timer: undefined };
        kept.set(key, fresh);
        // A failed connection is not kept.
        session.catch(() => forget(key, fresh));
        k = fresh;
      }
      const entry = k;
      entry.users++;
      entry.idleSince = null;
      timers.clearTimeout(entry.timer);
      let s: RequestSession;
      try {
        s = await entry.session;
      } catch (e) {
        entry.users--;
        throw e;
      }
      let released = false;
      return lease(s, () => {
        if (released) return;
        released = true;
        entry.users--;
        if (entry.users > 0) return;
        if (s.closed || kept.get(key) !== entry) {
          forget(key, entry);
          s.close();
          return;
        }
        entry.idleSince = options.now();
        watch(key, entry, s);
      });
    },
  };
}

/** A user's handle on a shared session: close() releases it instead of closing the session. */
function lease(s: RequestSession, release: () => void): IdentityChannel {
  return {
    get extensions() {
      return s.extensions;
    },
    host: (g) => s.host(g),
    open: (r) => s.open(r),
    control: (r, start) => s.control(r, start),
    putControl: (r, head, record) => s.putControl(r, head, record),
    keyPackages: (r, recipient, epochs) => s.keyPackages(r, recipient, epochs),
    putKeyPackage: (r, bytes) => s.putKeyPackage(r, bytes),
    dataUnits: (r, ranges) => s.dataUnits(r, ranges),
    putDataUnit: (r, bytes) => s.putDataUnit(r, bytes),
    close: release,
  };
}
