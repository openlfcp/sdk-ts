// Why a WebSocket upgrade failed, in Node (501, decision I18, spike B-001
// gap G6). Node's WebSocket (undici) reports a refused upgrade as a bare
// error event and a close 1006, without the HTTP status; a plain GET does
// not tell either, because the server answers it 400 before its rate check.
// So the probe repeats the upgrade request with node:http(s): a 429 is
// read with its Retry-After; anything else, a 101 included (closed at
// once), is not a rate limit.

import { randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { UpgradeProbe, UpgradeRefusal } from "@openlfcp/client";

/** Retry-After as milliseconds: delta-seconds or an HTTP date; undefined when absent or unreadable. */
export function retryAfterMs(value: string | undefined, now = Date.now()): number | undefined {
  if (value === undefined) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const at = Date.parse(v);
  return Number.isNaN(at) ? undefined : Math.max(0, at - now);
}

/**
 * An UpgradeProbe for Node: pass it as `upgradeProbe` to SyncClient or
 * connectionNetwork (openNodeInstallation does). One HTTP request, only
 * after a WebSocket failed before it opened; `timeoutMs` bounds it.
 */
export function nodeUpgradeProbe(timeoutMs = 5000): UpgradeProbe {
  return (url, protocols) =>
    new Promise<UpgradeRefusal | undefined>((resolve) => {
      let u: URL;
      try {
        u = new URL(url);
      } catch {
        resolve(undefined);
        return;
      }
      const secure = u.protocol === "wss:" || u.protocol === "https:";
      const send = secure ? httpsRequest : httpRequest;
      const req = send(
        {
          protocol: secure ? "https:" : "http:",
          hostname: u.hostname,
          port: u.port === "" ? (secure ? 443 : 80) : Number(u.port),
          path: `${u.pathname}${u.search}`,
          method: "GET",
          // Its own connection, never pooled: it is closed with its answer.
          agent: false,
          headers: {
            connection: "Upgrade",
            upgrade: "websocket",
            "sec-websocket-version": "13",
            "sec-websocket-key": randomBytes(16).toString("base64"),
            ...(protocols.length === 0 ? {} : { "sec-websocket-protocol": protocols.join(", ") }),
          },
          timeout: timeoutMs,
        },
        (res) => {
          res.resume();
          res.socket.destroy();
          const after = res.headers["retry-after"];
          resolve(
            res.statusCode === 429
              ? (() => {
                  const ms = retryAfterMs(Array.isArray(after) ? after[0] : after);
                  return ms === undefined ? { status: 429 } : { status: 429, retryAfterMs: ms };
                })()
              : undefined,
          );
        },
      );
      // Admitted this time: not a rate limit; the connection is not used.
      req.on("upgrade", (_res, socket) => {
        socket.destroy();
        resolve(undefined);
      });
      req.on("timeout", () => req.destroy());
      req.on("error", () => resolve(undefined));
      req.end();
    });
}
