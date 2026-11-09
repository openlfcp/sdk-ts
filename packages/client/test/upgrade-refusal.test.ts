// 501 (G6, decision I18): a SyncClient whose upgrade the server refuses
// with HTTP 429 says so (the connection event's rateLimited, learned by an
// upgrade probe) and does not try again before the server's Retry-After.

import { InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import { describe, expect, it } from "vitest";
import {
  OutboundQueue,
  SyncClient,
  type SyncEvent,
  type WebSocketFactory,
  type WebSocketLike,
} from "../src/index.js";
import { settle } from "./fake-server.js";
import { party } from "./identity/support.js";

function refusing() {
  let opened = 0;
  const factory: WebSocketFactory = () => {
    opened++;
    const ws: WebSocketLike = {
      binaryType: "arraybuffer",
      protocol: "",
      onopen: null,
      onmessage: null,
      onclose: null,
      onerror: null,
      send: () => undefined,
      close: () => undefined,
    };
    queueMicrotask(() => {
      ws.onerror?.({});
      ws.onclose?.({ code: 1006, reason: "" });
    });
    return ws;
  };
  return { factory, opened: () => opened };
}

describe("SyncClient and a rate-limited upgrade (501)", () => {
  it("reports rateLimited and waits at least Retry-After before the next attempt", async () => {
    let t = 1_000_000;
    const ws = refusing();
    const storage = new InMemoryLfcpStorage();
    const sync = new SyncClient({
      url: "ws://127.0.0.1:1/v1/ws",
      signer: party(1).signer,
      agreement: party(1).agreement,
      storage,
      secrets: new InMemorySecretStore(),
      outbound: new OutboundQueue({ storage }),
      now: () => t,
      webSocket: ws.factory,
      reconnect: () => 1000,
      upgradeProbe: async () => ({ status: 429, retryAfterMs: 7000 }),
    });
    const events: SyncEvent[] = [];
    sync.on((e) => events.push(e));
    sync.start();
    await settle(50);
    // The state change comes first; the loss itself carries the reason.
    const lost = events.find((e) => e.type === "connection" && e.reason !== undefined);
    expect(lost).toMatchObject({ rateLimited: { status: 429, retryAfterMs: 7000 } });
    expect(ws.opened()).toBe(1);
    // The policy says 1 s; the server said 7 s.
    t += 1500;
    sync.tick(t);
    await settle(50);
    expect(ws.opened()).toBe(1);
    t += 6000;
    sync.tick(t);
    await settle(50);
    expect(ws.opened()).toBe(2);
    await sync.stop();
  });
});
