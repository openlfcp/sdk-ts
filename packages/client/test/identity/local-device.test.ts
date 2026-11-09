// 504 (spike B-001 gaps G1, G4): what a paired installation knows about
// itself offline. pairedResources and deviceIdentity read the pairing
// journal and the stored chains; completePairing({storeResources}) and
// storePairedResources give a headless device Resource rows to list.

import { bytesEqual, toHex } from "@openlfcp/core";
import type { InMemoryLfcpStorage } from "@openlfcp/storage";
import { activeDevice, DEVICE_KIND } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { OperationJournal } from "../../src/identity/journal.js";
import {
  deviceIdentity,
  pairedResources,
  storePairedResources,
} from "../../src/identity/local-device.js";
import {
  approvePairing,
  createPairingSession,
  pairingRequests,
} from "../../src/identity/pairing.js";
import { completePairing, requestPairing } from "../../src/identity/pairing-request.js";
import { revocationStatus } from "../../src/identity/proof.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import { loadControlChain } from "../../src/storage.js";
import { party, URL } from "./support.js";
import { node, pair, world } from "./world.js";

/** The test world's storage is an InMemoryLfcpStorage: its Resource rows. */
const rows = (n: { storage: unknown }) => (n.storage as InMemoryLfcpStorage).resources;

async function service(storeResources: boolean | undefined) {
  const w = await world(2);
  const [X, Y] = w.resources as unknown as [Uint8Array, Uint8Array];
  const s = await createPairingSession(w.P);
  if (s.kind !== "created") throw new Error(s.kind);
  const S = node(w.server, party(5));
  expect(await pairedResources(S)).toEqual([]);
  expect(await deviceIdentity(S)).toBeUndefined();
  const req = await requestPairing({
    ...S,
    link: s.link,
    label: "bridge",
    kind: 1,
    scope: [X, Y] as never,
  });
  if (req.kind !== "requested") throw new Error(req.kind);
  const [review] = await pairingRequests({ ...w.P, session: s.session });
  if (review === undefined) throw new Error("none");
  const approved = await approvePairing({ ...w.P, review, preset: "service", scope: [X as never] });
  if (approved.kind !== "approved") throw new Error(approved.kind);
  // Before the approval is learned, nothing is known locally.
  expect(await pairedResources(S)).toEqual([]);
  const done = await completePairing({
    ...S,
    operation: req.operation,
    ...(storeResources === undefined ? {} : { storeResources }),
  });
  if (done.kind !== "approved") throw new Error(done.kind);
  expect(done.candidates.map((c) => c.status)).toEqual(["ready", "not-granted"]);
  return { w, S, X, Y };
}

describe("a paired service installation, offline (504)", { timeout: 60_000 }, () => {
  test("completePairing({ storeResources }) stores a row for each ready candidate only", async () => {
    const { S, X } = await service(true);
    const stored = await rows(S).list();
    expect(stored.map((r) => toHex(r.resourceId))).toEqual([toHex(X)]);
    expect(stored[0]?.labels).toEqual({});
    expect(
      bytesEqual(
        stored[0]?.localPrincipal?.principalId as Uint8Array,
        party(5).signer.descriptor.principalId,
      ),
    ).toBe(true);
  });

  test("by default no row is written (an application stores its own); pairedResources still lists them", async () => {
    const { S, X, Y } = await service(undefined);
    expect(await rows(S).list()).toEqual([]);
    const paired = await pairedResources(S);
    expect(paired.map((p) => [toHex(p.resource), p.ready, p.profile, p.url])).toEqual([
      [toHex(X), true, "org.example.v1", "wss://identity.example.test/v1/ws"],
      [toHex(Y), false, "org.example.v1", "wss://identity.example.test/v1/ws"],
    ]);
    // An installation paired before storeResources existed: rows from the journal, once.
    expect(
      (await storePairedResources({ ...S, storage: S.storage as InMemoryLfcpStorage })).map(toHex),
    ).toEqual([toHex(X)]);
    expect(await storePairedResources({ ...S, storage: S.storage as InMemoryLfcpStorage })).toEqual(
      [],
    );
    expect((await rows(S).list()).map((r) => toHex(r.resourceId))).toEqual([toHex(X)]);
  });

  test("deviceIdentity: the approved certificate's kind, mask and scope, the root, the label", async () => {
    const { w, S, X } = await service(false);
    const me = await deviceIdentity(S);
    if (me?.kind !== "device") throw new Error(String(me?.kind));
    expect(me.deviceKind).toBe(DEVICE_KIND.SERVICE);
    expect(me.mask).toEqual([1n, 2n]);
    expect(me.scope.map(toHex)).toEqual([toHex(X)]);
    expect(me.label).toBe("bridge");
    expect(toHex(me.root)).toBe(toHex(party(1).signer.descriptor.principalId));
    expect(toHex(me.device)).toBe(toHex(party(5).signer.descriptor.principalId));
    expect(toHex(me.identity)).toBe(toHex(w.I));
  });
});

describe("deviceIdentity of a root and of a personal device (504)", { timeout: 60_000 }, () => {
  test("the root is the installation that created the Identity Resource", async () => {
    const w = await world(1);
    const me = await deviceIdentity(w.P);
    expect(me).toEqual({
      kind: "root",
      identity: w.I,
      root: party(1).signer.descriptor.principalId,
      device: party(1).signer.descriptor.principalId,
      label: "laptop",
    });
  });

  test("a personal device: kind 0, its preset's mask, every roster Resource (empty scope)", async () => {
    const w = await world(1);
    const B = await pair(w, w.P, 3, "edit");
    const me = await deviceIdentity(B);
    if (me?.kind !== "device") throw new Error(String(me?.kind));
    expect([me.deviceKind, me.mask, me.scope, me.label]).toEqual([
      DEVICE_KIND.PERSONAL,
      [1n, 2n, 3n],
      [],
      "device 3",
    ]);
    // Its pairing brought I's roster: the raw Resource is ready.
    expect((await pairedResources(B)).map((p) => [toHex(p.resource), p.ready])).toEqual([
      [toHex(w.resources[0] as Uint8Array), true],
    ]);
  });
});

// Review #27 (r2): ready is completePairing's "ready", not "a chain and a key reference".
describe("what is not ready (504, r2)", { timeout: 60_000 }, () => {
  const readyOf = async (S: Parameters<typeof pairedResources>[0], X: Uint8Array) =>
    (await pairedResources(S)).find((p) => toHex(p.resource) === toHex(X))?.ready;

  test("a registration whose approval is not this request's (another digest): not ready, no row", async () => {
    const { S, X } = await service(false);
    expect(await readyOf(S, X)).toBe(true);
    const journal = new OperationJournal(S.storage);
    const [op] = await journal.list({ kind: "pairing-request" });
    if (op === undefined) throw new Error("no request");
    // The certificate registered in X is still active; the approval it must prove is another.
    await journal.updateIntent(op.id, { digest: "ab".repeat(32) });
    expect(await readyOf(S, X)).toBe(false);
    expect(await storePairedResources({ ...S, storage: S.storage as InMemoryLfcpStorage })).toEqual(
      [],
    );
    expect(await rows(S).list()).toEqual([]);
  });

  test("a Data Epoch key lost from the SecretStore, its row kept: not ready", async () => {
    const { S, X } = await service(false);
    const [epoch] = await S.storage.control.epochs(X as never);
    if (epoch?.dekRef === null || epoch?.dekRef === undefined) throw new Error("no dek ref");
    await S.secrets.delete(epoch.dekRef);
    expect((await S.storage.control.epochs(X as never))[0]?.dekRef).toBe(epoch.dekRef);
    expect(await readyOf(S, X)).toBe(false);
    expect(await storePairedResources({ ...S, storage: S.storage as InMemoryLfcpStorage })).toEqual(
      [],
    );
  });

  test("a revocation proven by revocationStatus, the local chain still old: not ready", async () => {
    const { w, S, X } = await service(false);
    await revokeDevice({ ...w.P, device: party(5).signer.descriptor.principalId, reason: 0n });
    const status = await revocationStatus({ ...S, resource: X as never, url: URL });
    expect(status.kind).toBe("revocation-proven");
    // The device's own stored chain does not show it.
    const chain = await loadControlChain(S.storage, X as never);
    if (chain?.kind !== "linear") throw new Error("no chain");
    expect(activeDevice(chain.state, party(5).signer.descriptor.principalId)).toBeDefined();
    expect(await readyOf(S, X)).toBe(false);
    expect(await storePairedResources({ ...S, storage: S.storage as InMemoryLfcpStorage })).toEqual(
      [],
    );
  });

  test("storePairedResources writes nothing for another installation on the same storage", async () => {
    const { S } = await service(false);
    const other = { ...S, installation: party(9), storage: S.storage as InMemoryLfcpStorage };
    expect(await storePairedResources(other)).toEqual([]);
    expect(await rows(S).list()).toEqual([]);
  });

  test("the row writer is not public", async () => {
    const api = await import("../../src/index.js");
    expect("putResourceRow" in api).toBe(false);
  });
});
