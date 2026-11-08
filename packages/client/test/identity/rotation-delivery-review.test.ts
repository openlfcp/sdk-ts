import { type ControlRecordId, type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import { parseKeyPackage, signControlRecord, validateControlChain } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  deliverKeys,
  heldDeks,
  IdentityConflict,
  type Installation,
  syncChain,
} from "../../src/identity/context.js";
import { OperationJournal, PackageLedger } from "../../src/identity/journal.js";
import { ChannelPool, IdentityUnavailable } from "../../src/identity/network.js";
import type { LinearChain } from "../../src/identity/phases.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import {
  deliveryIdentity,
  outstandingDeliveries,
  resumeRotations,
  rotateAfter,
} from "../../src/identity/rotation.js";
import { saveControlChain } from "../../src/storage.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { device, party, URL } from "./support.js";
import { hostResource, type Node, node, pair, world } from "./world.js";

// Review of task 416 (holistic review F1/F2 fix, sdk-ts 0.5.1), findings R1 and R2.
//
// R1: resumeRotations resumes each owed rotation on its own. A Resource whose
// coordinator refuses this installation's read (unhosted, read access revoked)
// keeps its obligation and is reported `refused` with the NACK's code; the
// next Resource's owed packages, to another person included, are delivered.
//
// R2: a supplied Identity chain never hides a revocation already stored: the
// newer of the supplied and the stored chain filters the delivery (two that
// diverge are a fork), resolved again at delivery time and for every resumed
// phase.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const hex = (b: Uint8Array) => toHex(b);

const sealedTo = (server: MemoryCoordinator, R: ResourceId, from: number) =>
  server.uploads
    .slice(from)
    .filter((e) => e.op === "key-package" && hex(e.resource) === hex(R))
    .map((e) => hex(parseKeyPackage(e.bytes).payload.recipient));

const hasKey = (server: MemoryCoordinator, R: ResourceId, who: PrincipalId, epoch: bigint) =>
  server.packagesOf(R).some((p) => hex(p.recipient) === hex(who) && p.dataEpoch === epoch);

/** `owner` grants `subject` `abilities` on R and seals R's keys to it; returns the grant's record ID. */
async function share(
  owner: Node,
  R: ResourceId,
  subject: Installation,
  abilities: bigint[],
): Promise<ControlRecordId> {
  const channel = await owner.network.connect(owner.installation.signer, URL);
  const x0 = await syncChain(owner.storage, channel, R);
  const grant = signControlRecord(
    { resourceId: R, controlSeq: x0.state.seq + 1n, prevControlId: x0.state.head },
    { type: "CAPABILITY_GRANT", subject: subject.signer.descriptor, abilities, delegable: [] },
    owner.installation.signer,
  );
  expect((await channel.putControl(R, x0.state.head, grant.bytes)).kind).toBe("ack");
  const x1 = await syncChain(owner.storage, channel, R);
  await deliverKeys({
    channel,
    ledger: new PackageLedger(owner.storage),
    chain: x1,
    sender: owner.installation.signer,
    recipients: [subject.signer.descriptor],
    deks: await heldDeks(owner.secrets, x1),
  });
  return grant.recordId as ControlRecordId;
}

/** `owner` revokes the grant `grantId` on R. */
async function unshare(owner: Node, R: ResourceId, grantId: ControlRecordId): Promise<void> {
  const channel = await owner.network.connect(owner.installation.signer, URL);
  const x = await syncChain(owner.storage, channel, R);
  const revoke = signControlRecord(
    { resourceId: R, controlSeq: x.state.seq + 1n, prevControlId: x.state.head },
    { type: "CAPABILITY_REVOKE", grantId },
    owner.installation.signer,
  );
  expect((await channel.putControl(R, x.state.head, revoke.bytes)).kind).toBe("ack");
}

/**
 * `n` rotates R under a journaled operation `operation`; the connection drops on
 * the new epoch's package to each of `owed`, so the rotation is committed, its
 * DEK adopted, and its delivery outstanding. Returns the new epoch.
 */
async function owedRotation(
  server: MemoryCoordinator,
  n: Node,
  R: ResourceId,
  operation: string,
  owed: readonly PrincipalId[],
): Promise<bigint> {
  await new OperationJournal(n.storage).begin({
    id: operation,
    kind: "rotate",
    createdAt: 1,
    intent: {},
  });
  const before = server.fault;
  server.fault = (e) =>
    e.op === "key-package" &&
    hex(e.resource) === hex(R) &&
    owed.some((o) => hex(o) === hex(parseKeyPackage(e.bytes).payload.recipient))
      ? "drop-request"
      : before(e);
  const channel = await n.network.connect(n.installation.signer, URL);
  const chain = await syncChain(n.storage, channel, R);
  await expect(
    rotateAfter({ ...n, channel, operation, resource: R, revokedAt: chain.state.seq }),
  ).rejects.toThrow(IdentityUnavailable);
  server.fault = before;
  const epoch = server.chain(R).state.epoch.epoch;
  expect((await outstandingDeliveries(n)).map((o) => [hex(o.resource), o.epoch])).toContainEqual([
    hex(R),
    epoch,
  ]);
  return epoch;
}

describe("R1: one owed Resource whose read is refused does not stop the others", {
  timeout: 120_000,
}, () => {
  for (const how of ["unhosted", "read access revoked"] as const)
    test(`X ${how}: Y's owed key reaches another person, X stays owed and reported`, async () => {
      const w = await world(1);
      const Q = node(w.server, party(9));
      // X: P's own section shared with Q, or another person Z's section P may rotate.
      const Z = node(w.server, party(8));
      const owner = how === "unhosted" ? w.P : Z;
      const X = (await hostResource(w.server, owner)).resource;
      let pGrant: ControlRecordId | undefined;
      if (how === "unhosted") await share(w.P, X, Q.installation, [1n, 2n]);
      else pGrant = await share(Z, X, w.P.installation, [1n, 2n, 6n, 7n]);
      const xOwed = how === "unhosted" ? id(9) : id(8);
      // Y: P's section shared with Q.
      const Y = (await hostResource(w.server, w.P)).resource;
      await share(w.P, Y, Q.installation, [1n, 2n]);
      // X's rotation first in the journal, then Y's: both delivered to nobody owed yet.
      const xEpoch = await owedRotation(w.server, w.P, X, "rotate.0-x", [xOwed]);
      const yEpoch = await owedRotation(w.server, w.P, Y, "rotate.1-y", [id(9)]);
      const yEpochs = w.server.chain(Y).state.epochs.size;
      // X now refuses P's reads: CONTROL_GET answers a NACK.
      if (how === "unhosted") w.server.hosted.delete(hex(X));
      else await unshare(Z, X, pGrant as ControlRecordId);
      const code = how === "unhosted" ? "RESOURCE_NOT_HOSTED" : "AUTHORIZATION_FAILED";
      // Ordinary reconciliation, twice: it resumes the owed rotations first.
      for (let run = 0; run < 2; run++) {
        await reconcileDevices(w.P);
        expect(hasKey(w.server, Y, id(9), yEpoch)).toBe(true);
        expect(w.server.chain(Y).state.epochs.size).toBe(yEpochs);
        const owed = await outstandingDeliveries(w.P);
        expect(owed.map((o) => hex(o.resource))).toEqual([hex(X)]);
        expect(owed[0]?.epoch).toBe(xEpoch);
        expect(owed[0]?.recipients).toEqual([hex(xOwed)]);
      }
      // resumeRotations reports X as refused, with the NACK's code.
      const pool = new ChannelPool(w.P.network);
      const out = await resumeRotations({ ...w.P, pool });
      pool.closeAll();
      expect(out.map((o) => [hex(o.resource), o.status, o.code])).toEqual([
        [hex(X), "refused", code],
      ]);
    });
});

/** I as P stores it: the linear chain. */
async function storedI(w: Awaited<ReturnType<typeof world>>): Promise<LinearChain> {
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  return syncChain(w.P.storage, channel, w.I);
}

describe("R2: a supplied Identity chain never hides a revocation stored here", {
  timeout: 120_000,
}, () => {
  test("deliveryIdentity: supplied old and stored new, supplied new and stored old, diverging", async () => {
    const w = await world(1);
    await pair(w, w.P, 3, "read");
    const I0 = await storedI(w);
    await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    const I1 = await storedI(w);
    expect(I1.records.length).toBeGreaterThan(I0.records.length);
    // Supplied old, stored new: the stored one.
    expect((await deliveryIdentity({ ...w.P, identityChain: I0 }))?.state.head).toEqual(
      I1.state.head,
    );
    // Supplied new, stored old: the supplied one.
    const old = device();
    expect((await saveControlChain(old.storage, I0 as never, null)).ok).toBe(true);
    expect(
      (await deliveryIdentity({ storage: old.storage, identityChain: I1 }))?.state.head,
    ).toEqual(I1.state.head);
    // Supplied, nothing stored: the supplied one.
    expect(
      (await deliveryIdentity({ storage: device().storage, identityChain: I0 }))?.state.head,
    ).toEqual(I0.state.head);
    // Two histories that diverge after I0: a fork, never chosen by length.
    const other = signControlRecord(
      { resourceId: w.I, controlSeq: I0.state.seq + 1n, prevControlId: I0.state.head },
      {
        type: "CAPABILITY_GRANT",
        subject: party(12).signer.descriptor,
        abilities: [1n],
        delegable: [],
      },
      w.P.installation.signer,
    );
    const branch = validateControlChain([...I0.records.map((r) => r.signed.bytes), other.bytes]);
    if (branch.kind !== "linear") throw new Error(branch.kind);
    await expect(deliveryIdentity({ ...w.P, identityChain: branch })).rejects.toThrow(
      IdentityConflict,
    );
  });

  test("resumed phases with a captured I: I's replay stores D's revocation, X's replay excludes D and its dependants", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const M = await pair(w, w.P, 2, "full"); // another managing device
    const D = await pair(w, w.P, 3, "full");
    await pair(w, D, 5, "read"); // E: its chain passes through D
    await pair(w, w.P, 6, "read"); // C: eligible
    // Owed rotations of I, then of X: C's, D's and E's new X key, and C's new I key, not sent.
    await owedRotation(w.server, w.P, w.I, "rotate.0-i", [id(6)]);
    const xEpoch = await owedRotation(w.server, w.P, X, "rotate.1-x", [id(6), id(3), id(5)]);
    // The upkeep's snapshot of I: D active.
    const I0 = await storedI(w);
    // M revokes D in I while X is unreachable: X still counts D (and E) as active.
    w.server.down.add(hex(X));
    await revokeDevice({ ...M, device: id(3), reason: 1n });
    w.server.down.clear();
    const from = w.server.uploads.length;
    // Resume with the captured I0: I's replay synchronises and stores I with D revoked.
    const pool = new ChannelPool(w.P.network);
    await resumeRotations({ ...w.P, pool, identityChain: I0 });
    pool.closeAll();
    const sealed = sealedTo(w.server, X, from);
    expect(hasKey(w.server, X, id(6), xEpoch)).toBe(true);
    expect(sealed).not.toContain(hex(id(3)));
    expect(sealed).not.toContain(hex(id(5)));
    expect(hasKey(w.server, X, id(3), xEpoch)).toBe(false);
    expect(hasKey(w.server, X, id(5), xEpoch)).toBe(false);
  });
});

describe("review extras", { timeout: 120_000 }, () => {
  test("the last owed reader loses its access before the replay: the delivery is done, nothing is sealed", async () => {
    const w = await world(1);
    const Q = node(w.server, party(9));
    const Y = (await hostResource(w.server, w.P)).resource;
    const grant = await share(w.P, Y, Q.installation, [1n, 2n]);
    await owedRotation(w.server, w.P, Y, "rotate.0-y", [id(9)]);
    await unshare(w.P, Y, grant);
    const from = w.server.uploads.length;
    const pool = new ChannelPool(w.P.network);
    const out = await resumeRotations({ ...w.P, pool });
    pool.closeAll();
    expect(out.map((o) => o.status)).toEqual(["rotated"]);
    expect(sealedTo(w.server, Y, from)).toEqual([]);
    expect(await outstandingDeliveries(w.P)).toEqual([]);
  });

  test("an installation without an Identity Resource: an owed rotation is resumed to every reader", async () => {
    const w = await world(0);
    const Z = node(w.server, party(8)); // no Identity Resource recorded
    const Q = node(w.server, party(9));
    const Y = (await hostResource(w.server, Z)).resource;
    await share(Z, Y, Q.installation, [1n, 2n]);
    const epoch = await owedRotation(w.server, Z, Y, "rotate.0-y", [id(9)]);
    expect(await deliveryIdentity(Z)).toBeUndefined();
    const pool = new ChannelPool(Z.network);
    const out = await resumeRotations({ ...Z, pool });
    pool.closeAll();
    expect(out.map((o) => o.status)).toEqual(["rotated"]);
    expect(hasKey(w.server, Y, id(9), epoch)).toBe(true);
    expect(await outstandingDeliveries(Z)).toEqual([]);
  });
});
