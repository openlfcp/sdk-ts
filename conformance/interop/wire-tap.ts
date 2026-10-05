// A WebSocket interposer for the live interop tests (LFCP-056, LFCP-057):
// it sits between a SyncClient and the server, sees every LFCP message in
// both directions as exact bytes, and can act on each one (record, drop,
// duplicate, delay, hold, or cut the connection). The client and server
// run their real code; only the transport between them is observed or
// disturbed. Test-only.

import { platformWebSocket, type WebSocketFactory, type WebSocketLike } from "@openlfcp/client";
import { type AnyMessage, decodeMessage } from "@openlfcp/wire";

declare const setTimeout: (fn: () => void, ms: number) => unknown;

export type Direction = "out" | "in";

/** One LFCP message as it crossed the tap. */
export interface Frame {
  readonly connection: number;
  readonly direction: Direction;
  readonly bytes: Uint8Array;
  /** The decoded message, or undefined when it does not decode. */
  readonly message: AnyMessage | undefined;
}

/** What to do with one message: deliver it (default), drop it, send it twice, delay it, or cut the connection after it. */
export type Action =
  | { readonly kind: "deliver" }
  | { readonly kind: "drop" }
  | { readonly kind: "duplicate" }
  | { readonly kind: "delay"; readonly ms: number }
  /** Deliver it, then close the connection (e.g. a request sent, its reply never seen). */
  | { readonly kind: "deliver-then-cut" }
  /** Cut the connection instead of delivering. */
  | { readonly kind: "cut" };

export type Rule = (frame: Frame) => Action | undefined;

const decode = (bytes: Uint8Array): AnyMessage | undefined => {
  try {
    return decodeMessage(bytes);
  } catch {
    return undefined;
  }
};

const toBytes = (data: unknown): Uint8Array | undefined => {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data))
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return undefined;
};

export class WireTap {
  readonly frames: Frame[] = [];
  #rules: Rule[] = [];
  #connections = 0;

  /** Adds a rule; the first rule that returns an action decides. Returns a remover. */
  rule(r: Rule): () => void {
    this.#rules.push(r);
    return () => {
      this.#rules = this.#rules.filter((x) => x !== r);
    };
  }

  #decide(frame: Frame): Action {
    for (const r of this.#rules) {
      const a = r(frame);
      if (a !== undefined) return a;
    }
    return { kind: "deliver" };
  }

  /** Every message of a type (by its §33 name), in order. */
  messages(type: string, direction?: Direction): Frame[] {
    return this.frames.filter(
      (f) => f.message?.type === type && (direction === undefined || f.direction === direction),
    );
  }

  /** The WebSocket factory to hand to a SyncClient. */
  readonly factory: WebSocketFactory = (url, protocols) => {
    const connection = ++this.#connections;
    const ws = platformWebSocket()(url, protocols);
    let onmessage: WebSocketLike["onmessage"] = null;
    const act = (frame: Frame, deliver: () => void) => {
      this.frames.push(frame);
      const action = this.#decide(frame);
      switch (action.kind) {
        case "deliver":
          deliver();
          return;
        case "drop":
          return;
        case "duplicate":
          deliver();
          deliver();
          return;
        case "delay":
          setTimeout(deliver, action.ms);
          return;
        case "deliver-then-cut":
          deliver();
          ws.close(4000, "cut by the test");
          return;
        case "cut":
          ws.close(4000, "cut by the test");
          return;
      }
    };
    ws.onmessage = (ev) => {
      const bytes = toBytes(ev.data);
      if (bytes === undefined) {
        onmessage?.(ev);
        return;
      }
      const copy = Uint8Array.from(bytes);
      act({ connection, direction: "in", bytes: copy, message: decode(copy) }, () =>
        onmessage?.({ data: copy.buffer }),
      );
    };
    return new Proxy(ws, {
      get(target, p) {
        if (p === "send")
          return (data: Uint8Array) => {
            const copy = Uint8Array.from(data);
            act({ connection, direction: "out", bytes: copy, message: decode(copy) }, () =>
              target.send(copy),
            );
          };
        if (p === "onmessage") return onmessage;
        const v = Reflect.get(target, p);
        return typeof v === "function" ? v.bind(target) : v;
      },
      set(target, p, v) {
        if (p === "onmessage") {
          onmessage = v as WebSocketLike["onmessage"];
          return true;
        }
        return Reflect.set(target, p, v);
      },
    }) as WebSocketLike;
  };
}

/** True when `needle` occurs in `haystack` (exact bytes). */
export function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0) return true;
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}
