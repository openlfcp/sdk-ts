import { type DataEpoch, type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import { parseKeyPackage } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { HINT_RESEND_BACKOFF_MS } from "../../src/identity/hint-marks.js";
import { keyHints, resendKeys, setKeyHints } from "../../src/identity/hints.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { FakeIdentityDocument } from "./fake-document.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party } from "./support.js";
import { type Node, pair, world } from "./world.js";

// Key hints and "Re-send keys" (IDENTITY-PROFILE-01 §7.1 step 3, §3 AI4
// and AI5; design 419 (a), decision I31). A device writes its own
// `missing_keys` hint; a managing device's reconciliation re-seals the
// hinted epochs even where its ledger shows a sent package; resendKeys
// forgets the ledger for one device, for a Read device that cannot write a
// hint.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const hex = (b: Uint8Array) => toHex(b);

const hasKey = (server: MemoryCoordinator, X: ResourceId, who: PrincipalId, epoch: bigint) =>
  server.packagesOf(X).some((p) => hex(p.recipient) === hex(who) && p.dataEpoch === epoch);

/** The coordinator loses every Key Package of X sealed to `who` (the ledger still says sent). */
function losePackages(server: MemoryCoordinator, X: ResourceId, who: PrincipalId) {
  const h = server.hosted.get(hex(X));
  if (h === undefined) throw new Error("not hosted");
  h.packages = h.packages.filter((b) => hex(parseKeyPackage(b).payload.recipient) !== hex(who));
}

const epochOf = (server: MemoryCoordinator, X: ResourceId) => server.chain(X).state.epoch.epoch;

describe("setKeyHints and keyHints (§7.1 step 3, AI5)", { timeout: 120_000 }, () => {
  test("a Full device writes, reads back, leaves unchanged and clears its own hint", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const D = await pair(w, w.P, 3, "full");
    const e = epochOf(w.server, X);
    const missing = new Map<ResourceId, readonly DataEpoch[]>([[X, [e]]]);
    expect(await setKeyHints({ ...D, missing })).toEqual({ kind: "written" });
    expect(await setKeyHints({ ...D, missing })).toEqual({ kind: "unchanged" });
    const read = await keyHints(w.P);
    expect([...read.keys()].map(hex)).toEqual([hex(id(3))]);
    expect([...(read.get([...read.keys()][0] as PrincipalId)?.entries() ?? [])]).toEqual([
      [X, [e]],
    ]);
    expect(await setKeyHints({ ...D, missing: new Map() })).toEqual({ kind: "written" });
    expect((await keyHints(w.P)).size).toBe(0);
    expect(await setKeyHints({ ...D, missing: new Map() })).toEqual({ kind: "unchanged" });
  });

  test("a Read device and a service device do not write I: not-a-writer, nothing sent", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const R = await pair(w, w.P, 4, "read");
    const S = await pair(w, w.P, 5, "service", { kind: 1, scope: [X] });
    const before = w.server.uploads.length;
    const missing = new Map<ResourceId, readonly DataEpoch[]>([[X, [0n as DataEpoch]]]);
    expect(await setKeyHints({ ...R, missing })).toEqual({ kind: "not-a-writer" });
    expect(await setKeyHints({ ...S, missing })).toEqual({ kind: "not-a-writer" });
    expect(w.server.uploads.slice(before).filter((u) => u.op === "data-unit")).toEqual([]);
  });

  test("a document port without keyHints: unsupported, no label rewritten", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const D = await pair(w, w.P, 3, "full");
    const plain: Node = {
      ...D,
      document: () => {
        const doc = new FakeIdentityDocument();
        return {
          write: (a, i) => doc.write(a, i),
          receive: (p, a) => doc.receive(p, a),
          initialized: () => doc.initialized(),
          roster: () => doc.roster(),
          devices: () => doc.devices(),
          requests: () => doc.requests(),
          origins: (t, k) => doc.origins(t, k),
        };
      },
    };
    const before = w.server.uploads.length;
    expect(await setKeyHints({ ...plain, missing: new Map([[X, [0n as DataEpoch]]]) })).toEqual({
      kind: "unsupported",
    });
    expect(w.server.uploads.slice(before).filter((u) => u.op === "data-unit")).toEqual([]);
  });
});

describe("a hint, or resendKeys, brings a lost package back (§7.1 step 3)", {
  timeout: 120_000,
}, () => {
  test("a lost package the ledger records: reconciliation re-seals it only once the device hints", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const D = await pair(w, w.P, 3, "full");
    const e = epochOf(w.server, X);
    expect(hasKey(w.server, X, id(3), e)).toBe(true);
    losePackages(w.server, X, id(3));
    // Without a hint the ledger says sent: nothing is sealed again.
    await reconcileDevices({ ...w.P, rotate: false });
    expect(hasKey(w.server, X, id(3), e)).toBe(false);
    // D says it lacks X's epoch; the next reconciliation re-seals it.
    expect(await setKeyHints({ ...D, missing: new Map([[X, [e]]]) })).toEqual({
      kind: "written",
    });
    await reconcileDevices({ ...w.P, rotate: false });
    expect(hasKey(w.server, X, id(3), e)).toBe(true);
  });

  test("resendKeys: a Read device's lost package is sealed again, nothing to the others", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    await pair(w, w.P, 4, "read");
    await pair(w, w.P, 6, "read");
    const e = epochOf(w.server, X);
    losePackages(w.server, X, id(4));
    const before = w.server.uploads.length;
    const r = await resendKeys({ ...w.P, device: id(4), resource: X });
    expect(r.cleared).toBeGreaterThan(0);
    expect(hasKey(w.server, X, id(4), e)).toBe(true);
    const sealed = w.server.uploads
      .slice(before)
      .filter((u) => u.op === "key-package")
      .map((u) => hex(parseKeyPackage(u.bytes).payload.recipient));
    expect(new Set(sealed)).toEqual(new Set([hex(id(4))]));
  });
});

/** Key Packages to `who` uploaded to X from upload index `from` on, refused ones included. */
const uploadsTo = (server: MemoryCoordinator, X: ResourceId, who: PrincipalId, from: number) =>
  server.uploads
    .slice(from)
    .filter(
      (u) =>
        u.op === "key-package" &&
        hex(u.resource) === hex(X) &&
        hex(parseKeyPackage(u.bytes).payload.recipient) === hex(who),
    ).length;

// Review 419 round 2, P2-1 (the reviewer's probes A1 and A2): a hint is answered once.
describe("a hint is answered once (review 419 P2-1)", { timeout: 120_000 }, () => {
  test("A1: a hint nobody clears is re-sealed once, then not again until it changes or a day passes", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const D = await pair(w, w.P, 3, "full");
    const e = epochOf(w.server, X);
    losePackages(w.server, X, id(3));
    expect(await setKeyHints({ ...D, missing: new Map([[X, [e]]]) })).toEqual({ kind: "written" });
    // D never comes back. The first reconciliation answers the hint.
    let from = w.server.uploads.length;
    expect((await keyHints(w.P, { unanswered: true })).size).toBe(1);
    await reconcileDevices({ ...w.P, rotate: false });
    expect(uploadsTo(w.server, X, id(3), from)).toBe(1);
    // Answered: not again, and no longer an unanswered hint.
    expect((await keyHints(w.P, { unanswered: true })).size).toBe(0);
    expect((await keyHints(w.P)).size).toBe(1);
    from = w.server.uploads.length;
    await reconcileDevices({ ...w.P, rotate: false });
    await reconcileDevices({ ...w.P, rotate: false });
    expect(uploadsTo(w.server, X, id(3), from)).toBe(0);
    expect(w.server.packagesOf(X).filter((p) => hex(p.recipient) === hex(id(3))).length).toBe(1);
    // A day later it is answered again, once.
    const later = { ...w.P, now: () => 1 + HINT_RESEND_BACKOFF_MS };
    expect((await keyHints(later, { unanswered: true })).size).toBe(1);
    from = w.server.uploads.length;
    await reconcileDevices({ ...later, rotate: false });
    await reconcileDevices({ ...later, rotate: false });
    expect(uploadsTo(w.server, X, id(3), from)).toBe(1);
  });

  test("A1: a changed hint is answered again", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const D = await pair(w, w.P, 3, "full");
    const e = epochOf(w.server, X);
    losePackages(w.server, X, id(3));
    await setKeyHints({ ...D, missing: new Map([[X, [e]]]) });
    await reconcileDevices({ ...w.P, rotate: false });
    // D lost the key again and says so with another epoch set (here, I's epoch too).
    losePackages(w.server, X, id(3));
    const eI = epochOf(w.server, w.I);
    expect(
      await setKeyHints({
        ...D,
        missing: new Map([
          [X, [e]],
          [w.I, [eI]],
        ]),
      }),
    ).toEqual({ kind: "written" });
    const from = w.server.uploads.length;
    // X's hint is the same epoch set: answered; I's is new: answered now.
    await reconcileDevices({ ...w.P, rotate: false });
    expect(uploadsTo(w.server, X, id(3), from)).toBe(0);
    expect(uploadsTo(w.server, w.I, id(3), from)).toBe(1);
  });

  test("A2: a package the server refuses for good is tried once per day, not per reconciliation", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const D = await pair(w, w.P, 3, "full");
    const e = epochOf(w.server, X);
    losePackages(w.server, X, id(3));
    await setKeyHints({ ...D, missing: new Map([[X, [e]]]) });
    w.server.fault = (u) =>
      u.op === "key-package" && hex(parseKeyPackage(u.bytes).payload.recipient) === hex(id(3))
        ? { nack: "QUOTA_EXCEEDED" }
        : undefined;
    const from = w.server.uploads.length;
    for (let i = 0; i < 3; i++) await reconcileDevices({ ...w.P, rotate: false });
    expect(uploadsTo(w.server, X, id(3), from)).toBe(1);
    expect((await keyHints(w.P, { unanswered: true })).size).toBe(0);
  });
});
