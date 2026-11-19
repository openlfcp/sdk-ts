// E-014: the write budget of the control Resource C (ARCHITECTURE A§3.5)
// against the reference server's write quotas, on real units: changes
// written through ServiceControlReplica.write, framed by the profile codec,
// encrypted and signed as Data Units. The synthetic year itself (size, cold
// connect, memory, admission time) is the bridge's job (E-030); this checks
// that a history within the budget, and the write rate the pacing of A§3.5
// allows, stay inside the server's default quotas, and that the mandatory
// heartbeat alone fits the budget.

import {
  actorSequence,
  dataEpoch,
  type PrincipalId,
  principalId,
  resourceId,
  secureRandom,
  toBase64url,
} from "@openlfcp/core";
import { importAgreementKey, importResourceDEK, importSigningKey } from "@openlfcp/crypto";
import {
  deviceFingerprint,
  ENTRY_LIMIT,
  PAIRING_ENTRY_LIMIT,
  type ServiceControlIntent,
  ServiceControlReplica,
  type ServiceControlSignerClass,
  serviceControlCodecFor,
} from "@openlfcp/shared-objects/service-control";
import {
  createMessage,
  DEFAULT_MAX_MESSAGE_BYTES,
  encodeMessage,
  encodePrincipalDescriptor,
  principalDescriptorFromKeys,
  type Signer,
  sealDataUnit,
} from "@openlfcp/wire";
import { describe, expect, it } from "vitest";

declare const console: { info(...a: unknown[]): void };

const MIB = 1024 * 1024;
/** A§3.5: one year of C's history on the server. */
const HISTORY_BUDGET_PER_YEAR = 20 * MIB;
/** A§3.5 / SERVICE-CONTROL-PROFILE-01 §9: a heartbeat at least every 30 minutes. */
const HEARTBEATS_PER_YEAR = 2 * 24 * 365;
/** A§3.5: transitions at most once a minute per binding; A§5.2: at most 8 sections. */
const BINDINGS = 8;
/**
 * The reference server's default write limits (server.lock: crates/lfcp-server/
 * src/limits.rs, AbuseLimits::default): quota mode is its default hosting.
 */
const SERVER = {
  quotaBytesPerResource: 128 * MIB,
  quotaBytesPerPrincipal: 256 * MIB,
  wsMessagesPerSecond: 50,
  wsMessageBurst: 200,
};

const seed = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n + i) & 0xff);
const party = (n: number): Signer => {
  const key = importSigningKey(seed(n));
  return { key, descriptor: principalDescriptorFromKeys(key, importAgreementKey(seed(n + 100))) };
};
const ROOT = party(41);
const BRIDGE = party(42);
const C = resourceId(seed(150));
const DEK = importResourceDEK(seed(151));
const T0 = "2026-11-19T10:00:00Z";
const id = (s: Signer): PrincipalId => principalId(s.descriptor.principalId);
const uid = (n: number) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;

/** C with its base approval, service and status, as a running bridge has it. */
function running() {
  const c = ServiceControlReplica.empty({ resource: C, root: id(ROOT), genesisSigner: id(ROOT) });
  let seq = 0;
  const write = (
    signer: Signer,
    signerClass: ServiceControlSignerClass,
    intents: ServiceControlIntent[],
  ) => {
    seq++;
    const change = c.write({ signer: id(signer), signerClass, actorSeq: seq }, intents);
    if (change === null) throw new Error("no change");
    const plaintext = serviceControlCodecFor({ resourceId: C, actor: id(signer) }).encode(change);
    const unit = sealDataUnit(
      {
        resourceId: C,
        dataEpoch: dataEpoch(0n),
        actorSeq: actorSequence(BigInt(seq)),
        prevDataUnitId: null,
        controlHead: seed(160) as never,
      },
      plaintext,
      DEK,
      signer,
    );
    return unit.bytes;
  };
  write(ROOT, "root", [{ intent: "initialize", attemptId: "attempt-1", createdAt: T0 }]);
  write(ROOT, "root", [
    {
      intent: "approval.create",
      approval: {
        role: "base",
        resource: toBase64url(C),
        principal: `p:${toBase64url(id(BRIDGE))}`,
        certDigest: toBase64url(seed(1)),
        certId: toBase64url(seed(2)),
        generation: 0,
        origin: "attempt-1",
        at: T0,
      },
    },
  ]);
  write(BRIDGE, "service-device", [
    {
      intent: "service.put",
      fields: {
        instance: "inst-1",
        kind: "apple-reminders",
        label: "MacBook Air",
        platform: "macos",
        app: "0.6.0",
        protocol: { v: 1, ops: ["check"], questionKinds: ["mass-delete"] },
        artifactSliceId: "arm64",
        macos: "15.1",
        cert: { state: "certified", manifestSeq: 1, certTestMode: false },
        capacity: { sections: 1, max: 8, devicesFree: 20 },
      },
    },
    { intent: "status.put", fields: { state: "running", since: T0, heartbeatAt: T0 } },
  ]);
  return { c, write };
}

const minute = (n: number) =>
  new Date(Date.parse(T0) + n * 60_000).toISOString().replace(/\.\d{3}Z$/, "Z");

describe("A§3.5 budget of C against the server's write quotas (E-014)", () => {
  it("the mandatory heartbeat of a year fits the history budget", () => {
    const { write } = running();
    // A heartbeat unit: one field of status written (the steady state, nothing else changes).
    const sizes = [1, 2, 3].map((n) =>
      write(BRIDGE, "service-device", [
        { intent: "status.put", fields: { heartbeatAt: minute(30 * n) } },
      ]),
    );
    const heartbeat = Math.max(...sizes.map((u) => u.length));
    const year = heartbeat * HEARTBEATS_PER_YEAR;
    console.info(
      `E-014 budget: heartbeat unit ${heartbeat} B, ${HEARTBEATS_PER_YEAR} a year = ${(year / MIB).toFixed(2)} MiB`,
    );
    expect(year).toBeLessThan(HISTORY_BUDGET_PER_YEAR / 2);
  });

  it("a history within the budget stays under the server's byte quotas", () => {
    // A§3.5 makes exceeding the budget a release blocker (E-030): at the budget,
    // C alone takes a sixth of a Resource's quota and leaves the root's
    // Principal quota for its sections for years.
    expect(HISTORY_BUDGET_PER_YEAR).toBeLessThan(SERVER.quotaBytesPerResource / 6);
    expect(SERVER.quotaBytesPerPrincipal - HISTORY_BUDGET_PER_YEAR).toBeGreaterThan(200 * MIB);
  });

  it("the busiest minute the pacing allows stays under the server's message rate", () => {
    const { write } = running();
    // One heartbeat and one transition for each binding, all in one minute.
    let units = 0;
    write(BRIDGE, "service-device", [{ intent: "status.put", fields: { heartbeatAt: minute(1) } }]);
    units++;
    for (let b = 0; b < BINDINGS; b++) {
      write(BRIDGE, "service-device", [
        {
          intent: "binding.put",
          binding: toBase64url(seed(200 + b)),
          fields: {
            state: "on",
            generation: 1,
            list: "Groceries",
            filter: "all",
            lastCompleteCheckAt: minute(1),
            pending: { toApple: 0, toLfcp: 0 },
            refused: 0,
            unconfirmed: 0,
          },
        },
      ]);
      units++;
    }
    expect(units).toBeLessThanOrEqual(SERVER.wsMessageBurst);
    expect(units / 60).toBeLessThan(SERVER.wsMessagesPerSecond);
  });

  it("the largest entries §4 admits, of incompressible content, fit the message limit", () => {
    const filler = (n: number) => toBase64url(secureRandom(Math.ceil((n * 3) / 4))).slice(0, n);
    const rid = uid(1);
    const pairSection = (link: string): ServiceControlIntent => ({
      intent: "request.create",
      rid,
      request: {
        op: "pair-section",
        binding: toBase64url(seed(9)),
        generation: 1,
        args: { link },
        client: { app: "0.8.0", protocol: 1 },
        at: T0,
      },
    });
    const pairing = (note: string): ServiceControlIntent => ({
      intent: "pairing.create",
      rid,
      pairing: {
        descriptor: toBase64url(encodePrincipalDescriptor(BRIDGE.descriptor)),
        principal: `p:${toBase64url(id(BRIDGE))}`,
        fp: deviceFingerprint(id(BRIDGE)),
        note,
      },
    });
    /** The largest filler §4 admits, and the sealed unit of the entry it makes. */
    const largest = (limit: number, make: (n: number) => Uint8Array) => {
      let lo = 0;
      let hi = limit;
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        try {
          make(mid);
          lo = mid;
        } catch (e) {
          if ((e as { diagnostic?: string }).diagnostic !== "LIMIT_EXCEEDED") throw e;
          hi = mid - 1;
        }
      }
      const at = make(lo);
      expect(() => make(lo + 1)).toThrowError(
        expect.objectContaining({ diagnostic: "LIMIT_EXCEEDED" }),
      );
      return { filler: lo, unit: at };
    };
    const request = largest(ENTRY_LIMIT, (n) =>
      running().write(ROOT, "root", [pairSection(filler(n))]),
    );
    const pair = largest(PAIRING_ENTRY_LIMIT, (n) => {
      const r = running();
      r.write(ROOT, "root", [pairSection("link")]);
      return r.write(BRIDGE, "service-device", [pairing(filler(n))]);
    });
    // The entries are at their limits: the fillers take almost all of it.
    expect(request.filler).toBeGreaterThan(ENTRY_LIMIT - 300);
    expect(pair.filler).toBeGreaterThan(PAIRING_ENTRY_LIMIT - 300);
    console.info(
      `E-014 budget: largest request unit ${request.unit.length} B, pairing unit ${pair.unit.length} B`,
    );
    // A full DATA_PUT of the outbound queue (64 units, OutboundQueue's default) of the largest.
    const put = encodeMessage(
      createMessage("DATA_PUT", { resourceId: C, objects: Array(64).fill(pair.unit) }),
    );
    expect(put.length).toBeLessThan(DEFAULT_MAX_MESSAGE_BYTES);
    expect(pair.unit.length).toBeLessThan(PAIRING_ENTRY_LIMIT + 2048);
    expect(request.unit.length).toBeLessThan(ENTRY_LIMIT + 2048);
  });
});
