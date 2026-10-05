import { LfcpError, secureRandom } from "@openlfcp/core";
import {
  type AnyMessage,
  type ClientConnectionEvent,
  type ClientConnectionState,
  type ClientHandshakeConfig,
  type ClientSession,
  type ClientStep,
  clientConnectionTransition,
  clientReceive,
  createMessage,
  DEFAULT_MAX_MESSAGE_BYTES,
  decodeFrame,
  ERROR_CODE,
  encodeMessage,
  type ReadySession,
  startClientHandshake,
  type WireErrorName,
} from "@openlfcp/wire";

/**
 * One LFCP connection over a WebSocket (LFCP-WIRE-01 §30, §31, §34-§38,
 * §63), for the client sync session (LFCP-039a). Portable: it uses the
 * platform WebSocket (browsers, Electron/Obsidian and Node 24 all have
 * `globalThis.WebSocket`), injectable for tests; no node:* imports.
 *
 * - Requests the `lfcp-1` subprotocol and drops a connection that did not
 *   get it (§30, G-SM3).
 * - Binary frames only, one LFCP message per WebSocket message; a text
 *   frame or a message above the size limit in force is answered with
 *   ERROR and closes the connection (§31).
 * - The handshake is the pure one of LFCP-027 (startClientHandshake,
 *   clientReceive); the §63 state follows clientConnectionTransition.
 * - Heartbeat (§38): tick(now) sends PING when nothing was sent for the
 *   READY interval and treats 3 intervals without any LFCP message as a
 *   dead connection. Time comes from the caller; nothing here sets timers.
 */

/** The parts of the WHATWG WebSocket this client uses. */
export interface WebSocketLike {
  binaryType: string;
  readonly protocol: string;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { readonly data: unknown }) => void) | null;
  onclose: ((ev: { readonly code: number; readonly reason: string }) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}

/** Opens a WebSocket: `new WebSocket(url, protocols)` in production. */
export type WebSocketFactory = (url: string, protocols: readonly string[]) => WebSocketLike;

/** The platform WebSocket (globalThis.WebSocket); throws if the runtime has none. */
export function platformWebSocket(): WebSocketFactory {
  const ctor = (
    globalThis as { WebSocket?: new (url: string, protocols: string[]) => WebSocketLike }
  ).WebSocket;
  if (ctor === undefined)
    throw new LfcpError(
      "UNSUPPORTED_VALUE",
      "this runtime has no global WebSocket; inject a factory",
    );
  return (url, protocols) => new ctor(url, [...protocols]);
}

/** §30: the only LFCP subprotocol. */
export const LFCP_SUBPROTOCOL = "lfcp-1";

export interface ConnectionEvents {
  /** The §63 state changed. */
  state(state: ClientConnectionState): void;
  /** READY arrived: the session's parameters (§37). */
  ready(ready: ReadySession): void;
  /** A message after READY that the handshake does not consume. */
  message(message: AnyMessage): void;
  /** The connection is gone (DISCONNECTED); `reason` is for humans and never carries payloads. */
  closed(reason: string): void;
}

export interface ConnectionOptions extends ClientHandshakeConfig {
  readonly url: string;
  readonly webSocket?: WebSocketFactory;
  /** The current time in milliseconds (the caller's clock). */
  readonly now: () => number;
}

const BYTES = (data: unknown): Uint8Array | string | undefined => {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data))
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return undefined;
};

export class LfcpConnection {
  readonly #options: ConnectionOptions;
  readonly #events: ConnectionEvents;
  #socket: WebSocketLike | null = null;
  #state: ClientConnectionState = "DISCONNECTED";
  #session: ClientSession | null = null;
  #ready: ReadySession | null = null;
  #lastSent = 0;
  #lastReceived = 0;
  #closedReported = true;

  constructor(options: ConnectionOptions, events: ConnectionEvents) {
    this.#options = options;
    this.#events = events;
  }

  get state(): ClientConnectionState {
    return this.#state;
  }

  /** The READY parameters while the session is READY. */
  get ready(): ReadySession | null {
    return this.#ready;
  }

  #move(event: ClientConnectionEvent): void {
    const next = clientConnectionTransition(this.#state, event);
    if (next === undefined) return;
    if (next !== this.#state) {
      this.#state = next;
      this.#events.state(next);
    }
  }

  /** Opens the WebSocket (DISCONNECTED → CONNECTING). */
  connect(): void {
    if (this.#state !== "DISCONNECTED") return;
    this.#move("OPEN");
    this.#closedReported = false;
    this.#ready = null;
    const socket = (this.#options.webSocket ?? platformWebSocket())(this.#options.url, [
      LFCP_SUBPROTOCOL,
    ]);
    this.#socket = socket;
    socket.binaryType = "arraybuffer";
    socket.onopen = () => {
      if (socket !== this.#socket) return;
      if (socket.protocol !== LFCP_SUBPROTOCOL) {
        this.#drop("CONNECT_FAILED", `the server did not accept ${LFCP_SUBPROTOCOL}`);
        return;
      }
      this.#move("CONNECTED");
      const now = this.#options.now();
      this.#lastReceived = now;
      this.#apply(startClientHandshake(this.#options));
    };
    socket.onmessage = (ev) => {
      if (socket === this.#socket) this.#receive(ev.data);
    };
    socket.onclose = (ev) => {
      if (socket === this.#socket)
        this.#drop("CONNECTION_LOST", `the WebSocket closed (${ev.code})`, false);
    };
    socket.onerror = () => {
      if (socket === this.#socket) this.#drop("CONNECTION_LOST", "the WebSocket failed");
    };
  }

  #apply(step: ClientStep): void {
    const before = this.#session?.phase;
    this.#session = step.session;
    for (const m of step.send) this.#write(m);
    if (step.close) {
      this.#drop(
        before === "AUTHENTICATING" ? "AUTH_FAILURE" : "FATAL_ERROR",
        step.session.phase === "DISCONNECTED" ? step.session.reason : "handshake failure",
      );
      return;
    }
    if (step.session.phase === "AUTHENTICATING" && before === "NEGOTIATING")
      this.#move("CHALLENGED");
    if (step.session.phase === "READY" && before !== "READY") {
      this.#ready = step.session.ready;
      this.#move("READY_RECEIVED");
      this.#events.ready(step.session.ready);
    }
    if (step.deliver !== undefined) this.#events.message(step.deliver);
  }

  #limit(): number {
    return this.#ready === null ? DEFAULT_MAX_MESSAGE_BYTES : Number(this.#ready.maxMessageBytes);
  }

  #receive(data: unknown): void {
    const frame = BYTES(data);
    if (frame === undefined) return;
    const result = decodeFrame(
      typeof frame === "string" ? { kind: "text", data: frame } : { kind: "binary", data: frame },
      { maxMessageBytes: this.#limit() },
    );
    this.#lastReceived = this.#options.now();
    if (result.kind === "error") {
      this.#error(result.wireCode, result.reason);
      if (result.closesConnection)
        this.#drop("CONNECTION_LOST", `${result.wireCode}: ${result.reason}`);
      return;
    }
    if (this.#session === null) return;
    this.#apply(clientReceive(this.#session, result.message, this.#options));
  }

  #error(code: WireErrorName, diagnostic: string): void {
    this.#write(createMessage("ERROR", { code: ERROR_CODE[code], diagnostic }));
  }

  #write(message: AnyMessage): void {
    const socket = this.#socket;
    if (socket === null) return;
    socket.send(encodeMessage(message));
    this.#lastSent = this.#options.now();
  }

  /**
   * Sends one message on a READY session. A message above READY's size
   * limit is refused (MESSAGE_TOO_LARGE) and never sent.
   */
  send(message: AnyMessage): void {
    this.sendEncoded(encodeMessage(message));
  }

  /** Sends already encoded message bytes (e.g. an OutboundMessage) on a READY session. */
  sendEncoded(bytes: Uint8Array): void {
    if (this.#state !== "READY" || this.#socket === null)
      throw new LfcpError("UNSUPPORTED_VALUE", "the connection is not READY");
    if (bytes.length > this.#limit())
      throw new LfcpError(
        "MESSAGE_TOO_LARGE",
        `${bytes.length} bytes exceed the session limit ${this.#limit()}`,
      );
    this.#socket.send(bytes);
    this.#lastSent = this.#options.now();
  }

  /**
   * Heartbeat (§38), driven by the caller's clock: a PING when nothing was
   * sent for READY's interval, and a close when nothing arrived for three.
   * Returns false when the connection was declared dead.
   */
  tick(now: number): boolean {
    if (this.#state !== "READY" || this.#ready === null) {
      // A handshake that stalls is as dead as an idle session.
      if (
        (this.#state === "NEGOTIATING" || this.#state === "AUTHENTICATING") &&
        now - this.#lastReceived > 30_000
      ) {
        this.#drop("CONNECTION_LOST", "the handshake timed out");
        return false;
      }
      return true;
    }
    const h = Number(this.#ready.heartbeatMs);
    if (h <= 0) return true;
    if (now - this.#lastReceived > 3 * h) {
      this.#drop("CONNECTION_LOST", "no LFCP message for three heartbeat intervals (§38)");
      return false;
    }
    if (now - this.#lastSent >= h) this.#write(createMessage("PING", { payload: secureRandom(8) }));
    return true;
  }

  /** Closes the connection (normal closure). */
  close(reason = "closed by the client"): void {
    this.#drop("CONNECTION_LOST", reason);
  }

  #drop(event: ClientConnectionEvent, reason: string, closeSocket = true): void {
    const socket = this.#socket;
    this.#socket = null;
    this.#session = null;
    this.#ready = null;
    if (socket !== null) {
      socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null;
      if (closeSocket)
        try {
          socket.close(1000, reason.slice(0, 120));
        } catch {
          // already closing
        }
    }
    this.#move(event);
    if (this.#state !== "DISCONNECTED") this.#move("CONNECTION_LOST");
    if (!this.#closedReported) {
      this.#closedReported = true;
      this.#events.closed(reason);
    }
  }
}
