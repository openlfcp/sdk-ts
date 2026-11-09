// 504 (spike B-001 gaps G1, G4): what a paired installation knows about
// itself offline. pairedResources and deviceIdentity read the pairing
// journal and the stored chains; completePairing({storeResources}) and
// storePairedResources give a headless device Resource rows to list.

import { bytesEqual, toHex } from "@openlfcp/core";
import type { InMemoryLfcpStorage } from "@openlfcp/storage";
import { DEVICE_KIND } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
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
import { party } from "./support.js";
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
