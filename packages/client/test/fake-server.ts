import {
  type AnyMessage,
  decodeMessage,
  encodeMessage,
  type LfcpMessage,
  replyTo,
  type ServerSession,
  serverReceive,
  startServerSession,
  WIRE_PROFILE,
} from "@openlfcp/wire";
import type { WebSocketFactory, WebSocketLike } from "../src/index.js";

/**
 * A scripted in-memory WebSocket server for client tests: it runs the real
 * server handshake (serverReceive), then records every message and lets
 * the test answer, push or drop the connection. Deliveries are async
 * (microtasks), like a real socket.
 */
export class FakeServer {
  readonly sockets: FakeSocket[] = [];
  readonly received: AnyMessage[] = [];
  /** Answers a READY-state message; return the replies. */
  onMessage: (m: AnyMessage, server: FakeServer) => AnyMessage[] = () => [];
  protocol = "lfcp-1";
  heartbeatMs = 0n;
  maxMessageBytes = 1_000_000n;
  /** The durability READY advertises (§37). */
  durability = 2n;

  readonly factory: WebSocketFactory = (url, protocols) => {
    const s = new FakeSocket(this, url, [...protocols]);
    this.sockets.push(s);
    queueMicrotask(() => s.accept());
    return s;
  };

  get current(): FakeSocket {
    const s = this.sockets.at(-1);
    if (s === undefined) throw new Error("no socket");
    return s;
  }

  /** Pushes a message to the client on the current socket. */
  push(m: AnyMessage): void {
    this.current.deliver(encodeMessage(m));
  }

  /** The READY-state messages of a type, in order. */
  of<T extends AnyMessage["type"]>(type: T): Extract<AnyMessage, { type: T }>[] {
    return this.received.filter((m) => m.type === type) as Extract<AnyMessage, { type: T }>[];
  }

  reply<T extends LfcpMessage["type"]>(
    request: AnyMessage,
    type: T,
    body: Extract<LfcpMessage, { type: T }>["body"],
  ): void {
    this.push(replyTo(request, type as never, body as never));
  }
}

export class FakeSocket implements WebSocketLike {
  binaryType = "blob";
  protocol = "";
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { readonly data: unknown }) => void) | null = null;
  onclose: ((ev: { readonly code: number; readonly reason: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  closed: { code?: number; reason?: string } | null = null;
  #session: ServerSession = startServerSession();
  readonly sent: Uint8Array[] = [];

  constructor(
    readonly server: FakeServer,
    readonly url: string,
    readonly protocols: string[],
  ) {}

  accept(): void {
    this.protocol = this.protocols.includes(this.server.protocol) ? this.server.protocol : "";
    this.onopen?.({});
  }

  send(data: Uint8Array): void {
    if (this.closed !== null) return;
    this.sent.push(Uint8Array.from(data));
    const m = decodeMessage(data, { maxMessageBytes: Infinity });
    if (this.#session.phase !== "READY") {
      const step = serverReceive(this.#session, m, {
        serverId: new Uint8Array(32).fill(9),
        wireProfiles: [WIRE_PROFILE],
        maxMessageBytes: this.server.maxMessageBytes,
        durability: this.server.durability,
        heartbeatMs: this.server.heartbeatMs,
      });
      this.#session = step.session;
      for (const r of step.send) this.deliver(encodeMessage(r));
      return;
    }
    this.server.received.push(m);
    for (const r of this.server.onMessage(m, this.server)) this.deliver(encodeMessage(r));
  }

  /** Delivers raw frame data to the client, asynchronously. */
  deliver(data: Uint8Array | string): void {
    queueMicrotask(() => {
      if (this.closed === null)
        this.onmessage?.({
          data:
            typeof data === "string"
              ? data
              : data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
        });
    });
  }

  close(code?: number, reason?: string): void {
    this.closed = {
      ...(code === undefined ? {} : { code }),
      ...(reason === undefined ? {} : { reason }),
    };
  }

  /** The server side drops the connection. */
  drop(code = 1006): void {
    this.closed = { code };
    queueMicrotask(() => this.onclose?.({ code, reason: "" }));
  }
}

/** Lets queued microtasks and promise chains run. */
export const settle = async (rounds = 20): Promise<void> => {
  for (let i = 0; i < rounds; i++) await Promise.resolve();
};
