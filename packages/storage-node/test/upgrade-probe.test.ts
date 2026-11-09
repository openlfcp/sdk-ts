// nodeUpgradeProbe (501, G6): Node's WebSocket hides a refused upgrade's
// status; the probe repeats the upgrade request and reads a 429 with its
// Retry-After. Also the poll backoff of `lfcp-node pair` (I18).

import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import {
  nodeUpgradeProbe,
  PAIR_POLL_BACKOFF_MS,
  pairPollDelay,
  retryAfterMs,
} from "../src/index.js";

let srv: Server | undefined;
const stop = async () => {
  const s = srv;
  srv = undefined;
  if (s === undefined) return;
  s.closeAllConnections();
  await new Promise((r) => s.close(r));
};
afterEach(stop);

async function serve(
  handler: Parameters<typeof createServer>[1],
  upgrade?: boolean,
): Promise<string> {
  srv = createServer(handler);
  if (upgrade === true)
    srv.on("upgrade", (_req, socket) => {
      socket.on("error", () => undefined);
      socket.end(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
      );
    });
  await new Promise<void>((r) => srv?.listen(0, "127.0.0.1", r));
  const a = srv.address();
  if (a === null || typeof a === "string") throw new Error("no port");
  return `ws://127.0.0.1:${a.port}/v1/ws`;
}

describe("nodeUpgradeProbe", () => {
  it("reads a 429 and its Retry-After from the upgrade request", async () => {
    const seen: Record<string, string | string[] | undefined>[] = [];
    const url = await serve((req, res) => {
      seen.push(req.headers);
      res.writeHead(429, { "retry-after": "7" });
      res.end("too many new connections from this address\n");
    });
    expect(await nodeUpgradeProbe()(url, ["lfcp-1"])).toEqual({ status: 429, retryAfterMs: 7000 });
    expect(seen[0]?.upgrade).toBe("websocket");
    expect(seen[0]?.["sec-websocket-protocol"]).toBe("lfcp-1");
  });

  it("is undefined for any other answer, an accepted upgrade, or no server", async () => {
    let url = await serve((_req, res) => {
      res.writeHead(400);
      res.end();
    });
    expect(await nodeUpgradeProbe()(url, [])).toBeUndefined();
    await stop();
    url = await serve(() => undefined, true);
    expect(await nodeUpgradeProbe()(url, [])).toBeUndefined();
    await stop();
    expect(await nodeUpgradeProbe(500)(url, [])).toBeUndefined();
    expect(await nodeUpgradeProbe()("not a url", [])).toBeUndefined();
  });

  it("parses Retry-After as seconds or an HTTP date", () => {
    expect(retryAfterMs("3")).toBe(3000);
    const now = Date.parse("2026-11-10T00:00:00Z");
    expect(retryAfterMs("Tue, 10 Nov 2026 00:00:05 GMT", now)).toBe(5000);
    expect(retryAfterMs("Tue, 09 Nov 2026 23:59:00 GMT", now)).toBe(0);
    expect(retryAfterMs("soon")).toBeUndefined();
    expect(retryAfterMs(undefined)).toBeUndefined();
  });
});

describe("lfcp-node pair's poll pacing", () => {
  it("4, 8, 15, then every 30 s by default; --poll is a fixed interval", () => {
    expect([0, 1, 2, 3, 4, 9].map((s) => pairPollDelay(s))).toEqual([
      4000, 8000, 15_000, 30_000, 30_000, 30_000,
    ]);
    expect(PAIR_POLL_BACKOFF_MS).toEqual([4000, 8000, 15_000, 30_000]);
    expect(pairPollDelay(5, 2)).toBe(2000);
  });
});
