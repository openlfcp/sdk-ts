// 501 (decision I18): identity sessions reused across flow calls
// (connectionNetwork keepAliveMs), and a refused upgrade told apart as
// rate-limited through an upgrade probe.

import { generateResourceId } from "@openlfcp/core";
import { type AnyMessage, createMessage, replyTo } from "@openlfcp/wire";
import { describe, expect, it } from "vitest";
import type { WebSocketFactory, WebSocketLike } from "../../src/connection.js";
import { connectionNetwork, IdentityUnavailable } from "../../src/identity/network.js";
import { FakeServer, settle } from "../fake-server.js";
import { party } from "./support.js";

const URL = "wss://identity.example.test/v1/ws";

/** A server answering RESOURCE_OPEN, and PING as §38 asks. */
function server(): FakeServer {
  const s = new FakeServer();
  s.onMessage = (m: AnyMessage) =>
    m.type === "RESOURCE_OPEN"
      ? [replyTo(m, "RESOURCE_OPENED", { resourceId: m.body.resourceId, heads: [], haves: [] })]
      : m.type === "PING"
        ? [replyTo(m, "PONG", { payload: m.body.payload })]
        : [];
  return s;
}

/** Manual timers and clock for the kept sessions. */
function clock() {
  let now = 0;
  let next = 1;
  const timers = new Map<number, { at: number; fn: () => void }>();
  return {
    now: () => now,
    timers: {
      setTimeout: (fn: () => void, ms: number) => {
        const id = next++;
        timers.set(id, { at: now + ms, fn });
        return id;
      },
      clearTimeout: (h: unknown) => {
        timers.delete(h as number);
      },
    },
    async advance(ms: number) {
      const end = now + ms;
      for (;;) {
        const due = [...timers.entries()]
          .filter(([, t]) => t.at <= end)
          .sort((a, b) => a[1].at - b[1].at)[0];
        if (due === undefined) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await settle();
      }
      now = end;
    },
  };
}

describe("connectionNetwork session reuse (501, I18)", () => {
  it("without keepAliveMs every call opens its own WebSocket, as before", async () => {
    const s = server();
    const net = connectionNetwork({ now: () => 0, webSocket: s.factory });
    for (let i = 0; i < 3; i++) {
      const ch = await net.connect(party(1).signer, URL);
      expect((await ch.open(generateResourceId())).kind).toBe("opened");
      ch.close();
    }
    expect(s.sockets.length).toBe(3);
  });

  it("reuses one session per (Principal, coordinator) across calls, concurrent ones included", async () => {
    const s = server();
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: s.factory,
      keepAliveMs: 60_000,
      timers: c.timers,
    });
    const a = await net.connect(party(1).signer, URL);
    a.close();
    const [b, d] = await Promise.all([
      net.connect(party(1).signer, URL),
      net.connect(party(1).signer, URL),
    ]);
    // Two flows on one session: each gets its own reply.
    const [rb, rd] = await Promise.all([
      b.open(generateResourceId()),
      d.open(generateResourceId()),
    ]);
    expect([rb.kind, rd.kind]).toEqual(["opened", "opened"]);
    b.close();
    b.close(); // a second release is a no-op
    expect(s.current.closed).toBeNull();
    d.close();
    expect(s.sockets.length).toBe(1);
    // Another Principal (a pairing device J) has its own session.
    const j = await net.connect(party(2).signer, URL);
    j.close();
    expect(s.sockets.length).toBe(2);
  });

  it("an unrelated push is dropped; the next request still gets its own reply", async () => {
    const s = server();
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: s.factory,
      keepAliveMs: 60_000,
      timers: c.timers,
    });
    const a = await net.connect(party(1).signer, URL);
    s.push(createMessage("PING", { payload: new Uint8Array(8) }));
    s.push(
      replyTo(createMessage("PING", { payload: new Uint8Array(8) }), "PONG", {
        payload: new Uint8Array(8),
      }),
    );
    await settle();
    expect((await a.open(generateResourceId())).kind).toBe("opened");
    a.close();
  });

  it("closes an idle session after keepAliveMs, pinging meanwhile; the next call opens a new one", async () => {
    const s = server();
    s.heartbeatMs = 5000n;
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: s.factory,
      keepAliveMs: 30_000,
      timers: c.timers,
    });
    const a = await net.connect(party(1).signer, URL);
    a.close();
    await c.advance(20_000);
    expect(s.current.closed).toBeNull();
    // §38: an idle kept session sends PINGs (every heartbeat interval).
    expect(s.of("PING").length).toBeGreaterThanOrEqual(3);
    const b = await net.connect(party(1).signer, URL);
    b.close();
    expect(s.sockets.length).toBe(1);
    // b released at 20 s: idle until 50 s. The tick at 50 s closes it and sends nothing:
    // a PING right before the close would be answered after it (a server error, close 1006).
    await c.advance(29_500);
    expect(s.current.closed).toBeNull();
    const pings = s.of("PING").length;
    await c.advance(1000);
    expect(s.current.closed).not.toBeNull();
    expect(s.of("PING").length).toBe(pings);
    const d = await net.connect(party(1).signer, URL);
    d.close();
    expect(s.sockets.length).toBe(2);
  });

  it("close() ends the kept sessions at once; a later call opens a new one", async () => {
    const s = server();
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: s.factory,
      keepAliveMs: 60_000,
      timers: c.timers,
    });
    const a = await net.connect(party(1).signer, URL);
    a.close();
    net.close?.();
    await settle();
    expect(s.current.closed).not.toBeNull();
    const b = await net.connect(party(1).signer, URL);
    b.close();
    expect(s.sockets.length).toBe(2);
    net.close?.();
  });

  it("a session the server dropped is never reused", async () => {
    const s = server();
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: s.factory,
      keepAliveMs: 60_000,
      timers: c.timers,
    });
    const a = await net.connect(party(1).signer, URL);
    a.close();
    s.current.drop();
    await settle();
    const b = await net.connect(party(1).signer, URL);
    expect((await b.open(generateResourceId())).kind).toBe("opened");
    b.close();
    expect(s.sockets.length).toBe(2);
  });
});

/** A WebSocket the server refuses before it opens (what a 429 looks like to the platform). */
const refused: WebSocketFactory = () => {
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

describe("a refused upgrade (501, G6)", () => {
  it("is rate-limited, with Retry-After, when the probe learns a 429", async () => {
    const asked: string[] = [];
    const net = connectionNetwork({
      now: () => 0,
      webSocket: refused,
      upgradeProbe: async (url, protocols) => {
        asked.push(`${url} ${protocols.join(",")}`);
        return { status: 429, retryAfterMs: 7000 };
      },
    });
    const e = await net.connect(party(1).signer, URL).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(IdentityUnavailable);
    expect((e as IdentityUnavailable).reason).toBe("rate-limited");
    expect((e as IdentityUnavailable).retryAfterMs).toBe(7000);
    expect((e as Error).message).toContain("HTTP 429");
    expect(asked).toEqual([`${URL} lfcp-1`]);
  });

  it("is an ordinary failure without a probe, or when the probe finds no 429", async () => {
    for (const upgradeProbe of [undefined, async () => undefined]) {
      const net = connectionNetwork({
        now: () => 0,
        webSocket: refused,
        ...(upgradeProbe === undefined ? {} : { upgradeProbe }),
      });
      const e = await net.connect(party(1).signer, URL).catch((x: unknown) => x);
      expect(e).toBeInstanceOf(IdentityUnavailable);
      expect((e as IdentityUnavailable).reason).toBeUndefined();
      expect((e as Error).message).toContain("the WebSocket failed");
    }
  });
});

// Review #28 (r2).
describe("connectionNetwork reuse, races (501, r2)", () => {
  it("close() ends a session still connecting: its connect rejects at once, its socket is closed", async () => {
    let socket: (WebSocketLike & { closed?: boolean }) | undefined;
    // The server accepts the WebSocket and never answers the handshake.
    const silent: WebSocketFactory = () => {
      const ws: WebSocketLike & { closed?: boolean } = {
        binaryType: "arraybuffer",
        protocol: "lfcp-1",
        onopen: null,
        onmessage: null,
        onclose: null,
        onerror: null,
        send: () => undefined,
        close: () => {
          ws.closed = true;
        },
      };
      socket = ws;
      queueMicrotask(() => ws.onopen?.({}));
      return ws;
    };
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: silent,
      keepAliveMs: 60_000,
      timers: c.timers,
    });
    const pending = net.connect(party(1).signer, URL).then(
      () => "connected",
      (e: unknown) => (e instanceof IdentityUnavailable ? "unavailable" : String(e)),
    );
    await settle();
    net.close?.();
    const outcome = await Promise.race([
      pending,
      new Promise((r) => setTimeout(() => r("still waiting"), 200)),
    ]);
    expect(outcome).toBe("unavailable");
    expect(socket?.closed).toBe(true);
  });

  it("several calls after the kept session was dropped open exactly one new session", async () => {
    const s = server();
    const c = clock();
    const net = connectionNetwork({
      now: c.now,
      webSocket: s.factory,
      keepAliveMs: 60_000,
      timers: c.timers,
    });
    (await net.connect(party(1).signer, URL)).close();
    s.current.drop();
    await settle();
    const channels = await Promise.all([1, 2, 3].map(() => net.connect(party(1).signer, URL)));
    expect(s.sockets.length).toBe(2);
    const answers = await Promise.all(channels.map((ch) => ch.open(generateResourceId())));
    expect(answers.map((a) => a.kind)).toEqual(["opened", "opened", "opened"]);
    for (const ch of channels) ch.close();
    // The new session is the kept one: close() reaches it.
    net.close?.();
    await settle();
    expect(s.current.closed).not.toBeNull();
  });
});
