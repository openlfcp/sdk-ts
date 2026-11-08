import { type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import type { SecretRef, SecretStore } from "@openlfcp/storage";
import { decodeControlRecord, parseKeyPackage, signControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { deliverKeys, heldDeks, IdentityConflict, syncChain } from "../../src/identity/context.js";
import { PackageLedger, pendingDekRef } from "../../src/identity/journal.js";
import { ChannelPool } from "../../src/identity/network.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { revokeDevice, rotateIfExposed } from "../../src/identity/revocation.js";
import { outstandingDeliveries, resumeRotations } from "../../src/identity/rotation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { type Node, node, pair, world } from "./world.js";

// Holistic review of MVP 0.4, F1 and F2 (sdk-ts 0.5.1).
//
// F1: a rotation resumed or retried without the caller's Identity chain (a
// plugin's retry of an owed rotation) still applies IDENTITY-PROFILE-01 §7.1
// step 1: nothing is sealed to a device I has revoked while X still counts it
// as active, and nothing at all while I is forked (§9.7).
//
// F2: a committed rotation keeps its delivery owed until every eligible reader,
// of every root, has its package (§§8.2, 9.1, 9.2, 9.5): a crash after the DEK
// is adopted and before the first package, or a transport failure during
// delivery, is resumed by the next ordinary reconciliation without a new
// KEY_EPOCH, and stays listed by outstandingDeliveries until it is delivered.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const hex = (b: Uint8Array) => toHex(b);

/** The recipients (hex) of the Key Packages uploaded to X from upload index `from` on. */
const sealedTo = (server: MemoryCoordinator, X: ResourceId, from: number) =>
  server.uploads
    .slice(from)
    .filter((e) => e.op === "key-package" && hex(e.resource) === hex(X))
    .map((e) => hex(parseKeyPackage(e.bytes).payload.recipient));

const hasKey = (server: MemoryCoordinator, X: ResourceId, who: PrincipalId, epoch: bigint) =>
  server.packagesOf(X).some((p) => hex(p.recipient) === hex(who) && p.dataEpoch === epoch);

/** X refuses the revocation of `device` (as at the limit of W §17.5 rule 5). */
const refuseRevocationOf = (server: MemoryCoordinator, X: ResourceId, device: PrincipalId) => {
  server.fault = (e) => {
    if (e.op !== "control" || hex(e.resource) !== hex(X)) return undefined;
    const b = decodeControlRecord(e.bytes).body;
    return b.type === "DEVICE_REVOKE" && hex(b.device) === hex(device)
      ? { nack: "AUTHORIZATION_FAILED" }
      : undefined;
  };
};

/**
 * DEV_3, DEV_4 and DEV_6 paired; DEV_3 revoked in I while X was unreachable
 * (X counts it as active); DEV_5's revocation committed in X with the answer to
 * its KEY_EPOCH lost: the revocation operation owes a rotation of X.
 */
async function owedRotationWithUnpropagatedDevice() {
  const w = await world(1);
  const X = w.resources[0] as ResourceId;
  await pair(w, w.P, 3, "read");
  await pair(w, w.P, 5, "read");
  await pair(w, w.P, 6, "read");
  w.server.down.add(hex(X));
  await revokeDevice({ ...w.P, device: id(3), reason: 1n });
  w.server.down.clear();
  // DEV_3's revocation stays unpropagated in X from here on.
  refuseRevocationOf(w.server, X, id(3));
  const fault = w.server.fault;
  w.server.fault = (e) =>
    e.op === "control" &&
    hex(e.resource) === hex(X) &&
    decodeControlRecord(e.bytes).body.type === "KEY_EPOCH"
      ? "drop-answer"
      : fault(e);
  // X is reached for DEV_5 only: DEV_3's revocation is not proposed by revokeDevice there.
  const lost = await revokeDevice({ ...w.P, device: id(5), reason: 1n });
  if (lost.kind !== "revoked") throw new Error(lost.kind);
  const xr = lost.results.find((t) => hex(t.resource) === hex(X));
  expect(xr?.rotation?.status).toBe("unreachable");
  refuseRevocationOf(w.server, X, id(3));
  return { w, X, operation: lost.operation };
}

/** `storage` as seen while the Control Chain of `forked` is stored as a conflict (§9.7). */
function withConflict(storage: Node["storage"], forked: ResourceId): Node["storage"] {
  const control = new Proxy(storage.control, {
    get(target, key) {
      if (key === "conflict")
        return (r: ResourceId) =>
          hex(r) === hex(forked) ? Promise.resolve({ forked: true }) : target.conflict(r);
      const v = Reflect.get(target, key, target) as unknown;
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
  return new Proxy(storage, {
    get(target, key) {
      if (key === "control") return control;
      const v = Reflect.get(target, key, target) as unknown;
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  });
}

describe("F1: a resumed rotation keeps the Identity Resource's revocation filter (§7.1 step 1)", {
  timeout: 120_000,
}, () => {
  test("rotateIfExposed on the owed operation, without identityChain, seals nothing to the unpropagated device", async () => {
    const { w, X, operation } = await owedRotationWithUnpropagatedDevice();
    const before = w.server.uploads.length;
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    // The plugin's retry of an owed rotation (#handOver before 0.7.3): no identityChain.
    const r = await rotateIfExposed({ ...w.P, channel, operation, resource: X });
    expect(r.status).toBe("rotated");
    const sealed = sealedTo(w.server, X, before);
    expect(sealed).toContain(hex(id(6)));
    expect(sealed).not.toContain(hex(id(3)));
    const epoch = w.server.chain(X).state.epoch.epoch;
    expect(hasKey(w.server, X, id(3), epoch)).toBe(false);
  });

  test("resumeRotations without identityChain seals nothing to the unpropagated device", async () => {
    const { w, X } = await owedRotationWithUnpropagatedDevice();
    const before = w.server.uploads.length;
    const pool = new ChannelPool(w.P.network);
    const out = await resumeRotations({ ...w.P, pool });
    pool.closeAll();
    expect(out.find((o) => hex(o.resource) === hex(X))?.status).toBe("rotated");
    const sealed = sealedTo(w.server, X, before);
    expect(sealed).toContain(hex(id(6)));
    expect(sealed).not.toContain(hex(id(3)));
  });

  test("while I is forked, a resumed rotation seals nothing and stays owed", async () => {
    const { w, X, operation } = await owedRotationWithUnpropagatedDevice();
    const before = w.server.uploads.length;
    const forked = { ...w.P, storage: withConflict(w.P.storage, w.I) };
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    await expect(rotateIfExposed({ ...forked, channel, operation, resource: X })).rejects.toThrow(
      IdentityConflict,
    );
    const pool = new ChannelPool(w.P.network);
    const out = await resumeRotations({ ...forked, pool });
    pool.closeAll();
    expect(out.find((o) => hex(o.resource) === hex(X))).toMatchObject({
      status: "unreachable",
      code: "CONTROL_CONFLICT",
    });
    expect(sealedTo(w.server, X, before)).toEqual([]);
    // Resolved: the same operation delivers, still without DEV_3.
    const r = await rotateIfExposed({ ...w.P, channel, operation, resource: X });
    expect(r.status).toBe("rotated");
    expect(sealedTo(w.server, X, before)).not.toContain(hex(id(3)));
  });

  test("a rotation first filtered by reconciliation, then resumed without identityChain, keeps the filter", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    await pair(w, w.P, 3, "read");
    await pair(w, w.P, 4, "read");
    await pair(w, w.P, 6, "read");
    w.server.down.add(hex(X));
    await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    await revokeDevice({ ...w.P, device: id(4), reason: 1n });
    w.server.down.clear();
    refuseRevocationOf(w.server, X, id(3));
    // The reconciliation's rotation of X: DEV_6's new package is refused, so it stays owed.
    const fault = w.server.fault;
    let refusing = true;
    w.server.fault = (e) =>
      refusing &&
      e.op === "key-package" &&
      hex(e.resource) === hex(X) &&
      hex(parseKeyPackage(e.bytes).payload.recipient) === hex(id(6))
        ? { nack: "QUOTA_EXCEEDED" }
        : fault(e);
    const r = await reconcileDevices(w.P);
    const x = r.targets.find((t) => hex(t.resource) === hex(X));
    expect(x?.unpropagated?.map(hex)).toEqual([hex(id(3))]);
    expect(x?.rotation?.status).toBe("rotated");
    expect(x?.rotation?.keys?.skipped.map((s) => s.recipient)).toContain(hex(id(6)));
    refusing = false;
    const before = w.server.uploads.length;
    // The plugin's retry of the reconciliation's rotation, by its operation, without I.
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    const again = await rotateIfExposed({
      ...w.P,
      channel,
      operation: r.operation,
      resource: X,
    });
    expect(again.status).toBe("rotated");
    const sealed = sealedTo(w.server, X, before);
    expect(sealed).toContain(hex(id(6)));
    expect(sealed).not.toContain(hex(id(3)));
  });
});

/**
 * Root P (Identity Resource, roster X) shares X with another person Q
 * (party 9: data/read, X's key sealed to Q). DEV_3 and DEV_6 are P's
 * devices; DEV_3 is revoked in I while X is unreachable, so the next
 * reconciliation propagates the revocation and rotates X (an operation of
 * kind `reconcile`).
 */
async function sharedWithAnotherRoot() {
  const w = await world(1);
  const X = w.resources[0] as ResourceId;
  const Q = node(w.server, party(9));
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  const x0 = await syncChain(w.P.storage, channel, X);
  const grant = signControlRecord(
    { resourceId: X, controlSeq: x0.state.seq + 1n, prevControlId: x0.state.head },
    {
      type: "CAPABILITY_GRANT",
      subject: Q.installation.signer.descriptor,
      abilities: [1n, 2n],
      delegable: [],
    },
    w.P.installation.signer,
  ).bytes;
  expect((await channel.putControl(X, x0.state.head, grant)).kind).toBe("ack");
  const x1 = await syncChain(w.P.storage, channel, X);
  await deliverKeys({
    channel,
    ledger: new PackageLedger(w.P.storage),
    chain: x1,
    sender: w.P.installation.signer,
    recipients: [Q.installation.signer.descriptor],
    deks: await heldDeks(w.P.secrets, x1),
  });
  await pair(w, w.P, 3, "read");
  await pair(w, w.P, 6, "read");
  w.server.down.add(hex(X));
  await revokeDevice({ ...w.P, device: id(3), reason: 1n });
  w.server.down.clear();
  return { w, X, Q: id(9) };
}

class Crash extends Error {}

/** P's secrets, crashing the process right after a pending DEK slot of `X` is deleted. */
function crashAfterAdoption(secrets: SecretStore, X: ResourceId): SecretStore {
  const prefix = String(pendingDekRef(X, "")).slice(0, -1);
  return {
    put: (ref, value) => secrets.put(ref, value),
    get: (ref) => secrets.get(ref),
    delete: async (ref: SecretRef) => {
      await secrets.delete(ref);
      if (String(ref).startsWith(prefix)) throw new Crash("crash after the DEK was adopted");
    },
  };
}

describe("F2: a committed rotation's delivery survives a crash and a transport failure (§§8.2, 9.1, 9.5)", {
  timeout: 120_000,
}, () => {
  test("a crash after DEK adoption, before the first package: the next reconciliation delivers to every root", async () => {
    const { w, X, Q } = await sharedWithAnotherRoot();
    const epochs = w.server.chain(X).state.epochs.size;
    const before = w.server.uploads.length;
    await expect(
      reconcileDevices({ ...w.P, secrets: crashAfterAdoption(w.P.secrets, X) }),
    ).rejects.toThrow(Crash);
    // The KEY_EPOCH is committed, the DEK adopted, and no package was sent.
    const chain = w.server.chain(X);
    expect(chain.state.epochs.size).toBe(epochs + 1);
    const epoch = chain.state.epoch.epoch;
    expect(sealedTo(w.server, X, before)).toEqual([]);
    expect((await heldDeks(w.P.secrets, chain)).has(String(epoch))).toBe(true);
    // The installation restarts over the same stores: the handover is outstanding, Q included.
    const P: Node = { ...w.P, network: w.server.network() };
    const owed = await outstandingDeliveries(P);
    expect(owed).toHaveLength(1);
    expect(owed[0]?.epoch).toBe(epoch);
    expect(owed[0]?.recipients).toContain(hex(Q));
    expect(owed[0]?.recipients).toContain(hex(id(6)));
    expect(owed[0]?.recipients).not.toContain(hex(id(3)));
    // Ordinary upkeep: a new reconciliation, no new KEY_EPOCH.
    await reconcileDevices(P);
    expect(w.server.chain(X).state.epochs.size).toBe(epochs + 1);
    expect(hasKey(w.server, X, Q, epoch)).toBe(true);
    expect(hasKey(w.server, X, id(6), epoch)).toBe(true);
    expect(hasKey(w.server, X, id(3), epoch)).toBe(false);
    expect(await outstandingDeliveries(P)).toEqual([]);
  });

  test("a transport failure during delivery: the outstanding handover is listed, then delivered without a new KEY_EPOCH", async () => {
    const { w, X, Q } = await sharedWithAnotherRoot();
    const epochs = w.server.chain(X).state.epochs.size;
    // The connection drops on Q's package of the new epoch, until the server recovers.
    let dropping = true;
    w.server.fault = (e) =>
      dropping &&
      e.op === "key-package" &&
      hex(e.resource) === hex(X) &&
      hex(parseKeyPackage(e.bytes).payload.recipient) === hex(Q) &&
      parseKeyPackage(e.bytes).payload.dataEpoch === BigInt(epochs)
        ? "drop-request"
        : undefined;
    const first = await reconcileDevices(w.P);
    expect(first.targets.find((t) => hex(t.resource) === hex(X))?.status).toBe("unreachable");
    const epoch = w.server.chain(X).state.epoch.epoch;
    expect(w.server.chain(X).state.epochs.size).toBe(epochs + 1);
    expect(hasKey(w.server, X, Q, epoch)).toBe(false);
    expect((await outstandingDeliveries(w.P))[0]?.recipients).toContain(hex(Q));
    // Still failing: the next run leaves it outstanding, without another KEY_EPOCH.
    await reconcileDevices(w.P);
    expect(w.server.chain(X).state.epochs.size).toBe(epochs + 1);
    expect((await outstandingDeliveries(w.P))[0]?.recipients).toEqual([hex(Q)]);
    dropping = false;
    await reconcileDevices(w.P);
    expect(w.server.chain(X).state.epochs.size).toBe(epochs + 1);
    expect(hasKey(w.server, X, Q, epoch)).toBe(true);
    expect(hasKey(w.server, X, id(3), epoch)).toBe(false);
    expect(await outstandingDeliveries(w.P)).toEqual([]);
  });

  test("a journal row written by 0.5.0 (no delivery mark) still loads and resumes as before", async () => {
    const { w, X } = await owedRotationWithUnpropagatedDevice();
    // 0.5.0 phases have only revokedAt: strip what 0.5.1 added and resume.
    const { OperationJournal } = await import("../../src/identity/journal.js");
    const journal = new OperationJournal(w.P.storage);
    for (const op of await journal.list())
      for (const p of op.phases)
        if (p.kind === "rotate" && p.facts !== undefined)
          await journal.putPhase(op.id, { ...p, facts: { revokedAt: p.facts.revokedAt ?? "0" } });
    expect(await outstandingDeliveries(w.P)).toEqual([]);
    const pool = new ChannelPool(w.P.network);
    const out = await resumeRotations({ ...w.P, pool });
    pool.closeAll();
    expect(out.find((o) => hex(o.resource) === hex(X))?.status).toBe("rotated");
  });
});
