// Security review follow-up (H3/M9 pass over sdk-ts): every function that
// runs patterns or scans over untrusted input (remote Data Unit content,
// server messages, invitation URIs, pasted text) stays fast on adversarial
// input. Each case is ~100k characters and must finish within the budget;
// super-linear behaviour shows up as seconds at this size.

import { fromBase64url, fromHex, isObjectId } from "@openlfcp/core";
import {
  isLocalDate,
  isPrincipalRef,
  isReverseDomain,
  isUtcTimestamp,
  pointerToken,
} from "@openlfcp/shared-objects";
import { isSecretRef } from "@openlfcp/storage";
import { checkReceivedUrl, checkWriterUrl, parseInviteUri } from "@openlfcp/wire";
import { describe, expect, it } from "vitest";

const N = 100_000;
const BUDGET_MS = 200;
const quiet = (f: () => unknown) => () => {
  try {
    f();
  } catch {
    // refusing is fine; only the time matters
  }
};

const cases: [string, () => unknown][] = [
  ["local date: long digits", () => isLocalDate("1".repeat(N))],
  ["timestamp: long fraction", () => isUtcTimestamp(`2026-10-06T10:00:00.${"1".repeat(N)}x`)],
  ["timestamp: long digits", () => isUtcTimestamp("2".repeat(N))],
  ["reverse domain: long label", () => isReverseDomain(`${"a".repeat(N)}!`)],
  ["reverse domain: many labels", () => isReverseDomain(`${"a.".repeat(N / 2)}!`)],
  ["reverse domain: hyphen runs", () => isReverseDomain(`a${"-".repeat(N)}`)],
  ["reverse domain: label-hyphen mix", () => isReverseDomain(`${"a-".repeat(N / 2)}.b!`)],
  ["principal ref: long", () => isPrincipalRef(`p:${"A".repeat(N)}`)],
  ["pointer token: many ~ and /", () => pointerToken("~/".repeat(N / 2))],
  ["base64url: long valid", () => quiet(() => fromBase64url("A".repeat(N)))()],
  ["base64url: long invalid at end", () => quiet(() => fromBase64url(`${"A".repeat(N)}=`))()],
  ["hex: long", () => quiet(() => fromHex("ab".repeat(N / 2)))()],
  ["object id: long", () => isObjectId("0".repeat(N))],
  ["secret ref: long", () => isSecretRef(`lfcp-secret:${"a".repeat(N)}:${":".repeat(N)}`)],
  ["writer URL: long authority then #", quiet(() => checkWriterUrl(`wss://${"a".repeat(N)}#`))],
  ["writer URL: long path then #", quiet(() => checkWriterUrl(`wss://h/${"a".repeat(N)}#x#`))],
  ["writer URL: long scheme", quiet(() => checkWriterUrl(`${"a".repeat(N)}://h/`))],
  ["writer URL: long port digits", quiet(() => checkWriterUrl(`wss://h:${"1".repeat(N)}x/`))],
  ["writer URL: many colons", quiet(() => checkWriterUrl(`wss://${":".repeat(N)}/`))],
  ["writer URL: IPv6-ish brackets", quiet(() => checkWriterUrl(`wss://[${"1:".repeat(N / 2)}/`))],
  ["received URL: long scheme", quiet(() => checkReceivedUrl(`${"a".repeat(N)}:`))],
  [
    "invite URI: long",
    quiet(() => parseInviteUri(`lfcp://join/${"A".repeat(N)}#secret=${"B".repeat(N)}`)),
  ],
  [
    "invite URI: many query params",
    quiet(() => parseInviteUri(`lfcp://join/x?${"a=1&".repeat(N / 4)}#secret=y`)),
  ],
  [
    "invite URI: many percent escapes",
    quiet(() => parseInviteUri(`lfcp://join/${"%41".repeat(N / 3)}#secret=y`)),
  ],
  ["invite URI: many hashes", quiet(() => parseInviteUri(`lfcp://join/x${"#".repeat(N)}`))],
];

describe("no super-linear scan over untrusted input in sdk-ts", () => {
  for (const [name, run] of cases)
    it(`${name} within ${BUDGET_MS} ms`, () => {
      const t0 = performance.now();
      run();
      const ms = performance.now() - t0;
      expect(ms, `${name}: ${ms.toFixed(0)} ms`).toBeLessThan(BUDGET_MS);
    });
});

// The replaced checkWriterUrl (reference only).
function oldCheckWriterUrl(url: string): string {
  const refuse = (why: string): never => {
    throw new Error(`refusing to write an endpoint: ${why}`);
  };
  try {
    const control = [...url].some((ch) => {
      const c = ch.codePointAt(0) as number;
      return c < 0x20 || c === 0x7f;
    });
    if (control || /\s/.test(url)) refuse("the URL contains whitespace or control characters");
    const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]+)([^#]*)$/.exec(url);
    if (m === null) return refuse("not an absolute URL with an authority and no fragment");
    const scheme = (m[1] as string).toLowerCase();
    const authority = m[2] as string;
    if (authority.includes("@")) refuse("user information is not allowed in the URL");
    const host = (/^(\[[^\]]*\]|[^:]*)(:\d*)?$/.exec(authority)?.[1] ?? "").toLowerCase();
    if (host === "") refuse("the URL has no host");
    const loopback =
      host === "localhost" || host === "[::1]" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
    if (scheme === "wss") return "ok";
    if (scheme === "ws" && loopback) return "ok";
    refuse(
      scheme === "ws"
        ? "ws:// is only for loopback hosts; use wss://"
        : `scheme ${scheme} is not wss`,
    );
    return "ok";
  } catch (e) {
    return (e as Error).message;
  }
}
const newCheckWriterUrl = (url: string): string => {
  try {
    checkWriterUrl(url);
    return "ok";
  } catch (e) {
    return (e as Error).message;
  }
};

describe("the linear writer-URL check agrees with the regex it replaced", () => {
  it("on 20 000 random URLs", () => {
    let seed = 11;
    const next = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const pieces = [
      "wss",
      "ws",
      "http",
      "W+S.s-",
      "1x",
      ":",
      "//",
      "/",
      "?",
      "#",
      "@",
      "[",
      "]",
      "::1",
      "127.0.0.1",
      "localhost",
      "host",
      ":8080",
      "a",
      "%20",
      ".",
      "",
    ];
    for (let i = 0; i < 20_000; i++) {
      let url = "";
      const n = 1 + Math.floor(next() * 8);
      for (let k = 0; k < n; k++) url += pieces[Math.floor(next() * pieces.length)];
      expect(newCheckWriterUrl(url), url).toBe(oldCheckWriterUrl(url));
    }
  });
});
