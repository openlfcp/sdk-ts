// A request/response LFCP session for the live chaos tests (LFCP-057): the
// SDK's LfcpConnection (real handshake), but the test sends exact messages
// of its choosing (a stale CONTROL_PUT, a tampered or equivocating
// DATA_PUT, ...) and reads the server's answers. Test-only.

import { LfcpConnection, type WebSocketFactory } from "@openlfcp/client";
import { toHex } from "@openlfcp/core";
import { type AnyMessage, ERROR_CODE, type Signer } from "@openlfcp/wire";

declare const setTimeout: (fn: () => void, ms: number) => unknown;

const CODE_NAME = new Map<bigint, string>(Object.entries(ERROR_CODE).map(([k, v]) => [v, k]));

/** The §62 name of a NACK or ERROR code. */
export const codeName = (code: bigint): string => CODE_NAME.get(code) ?? `ERROR_${code}`;

export class RawSession {
  readonly #connection: LfcpConnection;
  readonly inbox: AnyMessage[] = [];
  #ready = false;
  #closed: string | null = null;
  #waiters: (() => void)[] = [];

  constructor(options: {
    url: string;
    signer: Signer;
    credential?: Uint8Array;
    webSocket?: WebSocketFactory;
  }) {
    this.#connection = new LfcpConnection(
      {
        url: options.url,
        signer: options.signer,
        now: () => Date.now(),
        ...(options.credential === undefined ? {} : { credential: options.credential }),
        ...(options.webSocket === undefined ? {} : { webSocket: options.webSocket }),
      },
      {
        state: () => undefined,
        ready: () => {
          this.#ready = true;
          this.#wake();
        },
        message: (m) => {
          this.inbox.push(m);
          this.#wake();
        },
        closed: (reason) => {
          this.#closed = reason;
          this.#wake();
        },
      },
    );
  }

  #wake(): void {
    const w = this.#waiters;
    this.#waiters = [];
    for (const f of w) f();
  }

  async #until<T>(take: () => T | undefined, what: string, ms: number): Promise<T> {
    const deadline = Date.now() + ms;
    for (;;) {
      const v = take();
      if (v !== undefined) return v;
      if (this.#closed !== null)
        throw new Error(`closed while waiting for ${what}: ${this.#closed}`);
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
      await new Promise<void>((r) => {
        this.#waiters.push(r);
        setTimeout(r, 50);
      });
    }
  }

  async connect(ms = 10_000): Promise<void> {
    this.#connection.connect();
    await this.#until(() => (this.#ready ? true : undefined), "READY", ms);
  }

  /** Sends a message and returns its first correlated reply. */
  async request(m: AnyMessage, ms = 10_000): Promise<AnyMessage> {
    this.#connection.send(m);
    const id = toHex(m.messageId);
    return this.#until(
      () => {
        const i = this.inbox.findIndex(
          (r) => r.correlationId !== undefined && toHex(r.correlationId) === id,
        );
        return i === -1 ? undefined : this.inbox.splice(i, 1)[0];
      },
      `the reply to ${m.type}`,
      ms,
    );
  }

  close(): void {
    this.#connection.close("raw session done");
  }
}
