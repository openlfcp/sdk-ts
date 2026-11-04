import { bytesEqual, type PrincipalId, toHex } from "@openlfcp/core";
import { parseControlRecord, parseKeyPackage } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import {
  heldDeks,
  loadIdentityDocument,
  sealIdentityUnit,
  syncChain,
} from "../../src/identity/context.js";
import { principalRefOf, resourceRef } from "../../src/identity/document.js";
import { OperationJournal } from "../../src/identity/journal.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { previewRevocation, revokeDevice } from "../../src/identity/revocation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { addToRoster, hostResource, type Node, pair, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const types = (server: MemoryCoordinator, R: Uint8Array): string[] =>
  server.chain(R as never).records.map((r) => r.body.type);
const epochPackages = (server: MemoryCoordinator, R: Uint8Array, epoch: bigint) =>
  server
    .packagesOf(R as never)
    .filter((p) => p.dataEpoch === epoch)
    .map((p) => toHex(p.recipient))
    .sort();
const currentEpoch = (server: MemoryCoordinator, R: Uint8Array) =>
  server.chain(R as never).state.epoch.epoch;

/** `who`'s Identity Resource document, as `who` loads it from the coordinator. */
async function openI(who: Node, I: Uint8Array) {
  const channel = await who.network.connect(who.installation.signer, URL);
  const chain = await syncChain(who.storage, channel, I as never);
  const doc = who.document(I as never, chain.state.owner.principalId);
  const deks = await heldDeks(who.secrets, chain);
  const load = await loadIdentityDocument({ channel, chain, deks, doc });
  return { channel, chain, doc, deks, load };
}

describe("revoking a device (IDENTITY-PROFILE-01 §8)", { timeout: 60_000 }, () => {
  test("a managing device: its descendant is suspended, I and X rotate, neither receives the new DEK", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const A = await pair(w, w.P, 2, "full");
    const B = await pair(w, A, 3, "edit");
    void B;
    const preview = await previewRevocation({ ...w.P, device: id(2) });
    expect(preview.selfDependent).toBe(false);
    expect(
      preview.resources.map((r) => [r.status, r.suspended.map(toHex), r.exposing, r.rotator]),
    ).toEqual([
      ["ok", [toHex(id(3))], true, true],
      ["ok", [toHex(id(3))], true, true],
    ]);
    const before = { I: currentEpoch(w.server, w.I), X: currentEpoch(w.server, X) };
    const r = await revokeDevice({ ...w.P, device: id(2), reason: 1n });
    if (r.kind !== "revoked") throw new Error(r.kind);
    expect(r.results.map((x) => [x.revoke, x.rotation?.status])).toEqual([
      ["revoked", "rotated"],
      ["revoked", "rotated"],
    ]);
    for (const [R, e] of [
      [w.I, before.I],
      [X, before.X],
    ] as const) {
      expect(currentEpoch(w.server, R)).toBe(e + 1n);
      // The revoked device and the suspended one receive nothing (§8.2).
      expect(epochPackages(w.server, R, e + 1n)).not.toContain(toHex(id(2)));
      expect(epochPackages(w.server, R, e + 1n)).not.toContain(toHex(id(3)));
      expect((await heldDeks(w.P.secrets, w.server.chain(R as never))).has(String(e + 1n))).toBe(
        true,
      );
    }
    // A second run is complete everywhere and proposes nothing new.
    const n = types(w.server, w.I).length;
    const again = await revokeDevice({ ...w.P, device: id(2), reason: 1n });
    expect(again.kind === "revoked" && again.results.map((x) => x.revoke)).toEqual([
      "complete",
      "complete",
    ]);
    expect(types(w.server, w.I).length).toBe(n + 0);
  });

  test("the display flag of a device with its own missing_keys hint: the hint stays the device's (AI5)", async () => {
    const w = await world(1);
    const A = await pair(w, w.P, 2, "full");
    const key = principalRefOf(id(2));
    const a = await openI(A, w.I);
    const own = a.doc.devices().get(key);
    if (own === undefined) throw new Error("no device entry");
    const hint = { [resourceRef(w.I as never)]: [0] };
    const bytes = await sealIdentityUnit({
      storage: A.storage,
      chain: a.chain,
      deks: a.deks,
      signer: A.installation.signer,
      doc: a.doc,
      latest: a.load.latest,
      intents: [{ intent: "device.put", key, entry: { ...own, missing_keys: hint } }],
    });
    expect((await a.channel.putDataUnit(w.I, bytes)).kind).toBe("ack");
    const r = await revokeDevice({ ...w.P, device: id(2), reason: 0n });
    if (r.kind !== "revoked") throw new Error(r.kind);
    const p = await openI(w.P, w.I);
    // The revoker writes the flag only: the document refuses another device's hint (AI5).
    expect(p.doc.devices().get(key)).toMatchObject({ revoked: true, missing_keys: hint });
  });

  test("a revoker whose chain passes through the target is refused (§8.1)", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const C = await pair(w, A, 4, "full");
    expect((await previewRevocation({ ...C, device: id(2) })).selfDependent).toBe(true);
    expect((await revokeDevice({ ...C, device: id(2), reason: 2n })).kind).toBe("self-dependent");
  });

  test("self-retirement commits the revocations only; rotation is left to another installation", async () => {
    const w = await world(1);
    const B = await pair(w, w.P, 3, "edit");
    const r = await revokeDevice({ ...B, device: id(3), reason: 0n });
    if (r.kind !== "revoked") throw new Error(r.kind);
    expect(r.results.map((x) => [x.revoke, x.rotation])).toEqual([
      ["revoked", undefined],
      ["revoked", undefined],
    ]);
    expect(types(w.server, w.I).at(-1)).toBe("DEVICE_REVOKE");
    // The root's next reconciliation rotates: the retirement removed a reader.
    const rec = await reconcileDevices(w.P);
    expect(rec.targets.map((t) => t.rotation?.status)).toEqual(["rotated", "rotated"]);
  });

  test("two managers revoke with different reasons: the second is complete and its rotation too (§9.2, F06)", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    await pair(w, w.P, 3, "edit");
    const first = await revokeDevice({ ...A, device: id(3), reason: 2n });
    expect(first.kind === "revoked" && first.results[0]?.rotation?.status).toBe("rotated");
    const second = await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    if (second.kind !== "revoked") throw new Error(second.kind);
    expect([second.results[0]?.revoke, second.results[0]?.rotation?.status]).toEqual([
      "complete",
      "not-needed",
    ]);
    const revokes = w.server
      .chain(w.I)
      .records.filter((r) => r.body.type === "DEVICE_REVOKE" && bytesEqual(r.body.device, id(3)));
    expect(revokes.length).toBe(1);
  });

  test("a lost ACK of the KEY_EPOCH: the resumed operation adopts its DEK and seals it (§9.1)", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    await pair(w, w.P, 2, "full");
    w.server.fault = (e) =>
      e.op === "control" &&
      toHex(e.resource) === toHex(X) &&
      parseControlRecord(e.bytes).payload.controlType === 4n
        ? "drop-answer"
        : undefined;
    const r = await revokeDevice({ ...w.P, device: id(2), reason: 1n });
    expect(r.kind === "revoked" && r.results.map((x) => [x.revoke, x.rotation?.status])).toEqual([
      ["revoked", "rotated"],
      ["revoked", "unreachable"],
    ]);
    w.server.fault = () => undefined;
    const op = (r as { operation: string }).operation;
    const resumed = await revokeDevice({ ...w.P, device: id(2), reason: 1n, operation: op });
    if (resumed.kind !== "revoked") throw new Error(resumed.kind);
    expect(resumed.results.map((x) => x.rotation?.status)).toEqual(["rotated", "rotated"]);
    expect(types(w.server, X).filter((t) => t === "KEY_EPOCH").length).toBe(1);
    expect(
      (await heldDeks(w.P.secrets, w.server.chain(X as never))).has(
        String(currentEpoch(w.server, X)),
      ),
    ).toBe(true);
    const phase = (await new OperationJournal(w.P.storage).load(op)).phases.find(
      (p) => p.id === `rotate:${toHex(X)}`,
    );
    expect(phase?.state).toBe("committed-own");
  });

  test("a roster Resource unreachable during the revocation is carried by reconciliation (§8.5, §7.1)", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    await pair(w, w.P, 2, "full");
    w.server.down.add(toHex(X));
    const r = await revokeDevice({ ...w.P, device: id(2), reason: 2n });
    expect(r.kind === "revoked" && r.results.map((x) => x.revoke)).toEqual([
      "revoked",
      "unreachable",
    ]);
    w.server.down.clear();
    const rec = await reconcileDevices(w.P);
    const x = rec.targets.find((t) => toHex(t.resource) === toHex(X));
    // The revocations of I's consumed pairing devices travel too (reason 3 as 0), then A's.
    expect(x?.steps.map((s) => [s.step.kind, s.state])).toEqual([
      ["revoke", "committed-own"],
      ["revoke", "committed-own"],
    ]);
    expect(toHex(x?.steps.at(-1)?.step.device as Uint8Array)).toBe(toHex(id(2)));
    expect(x?.rotation?.status).toBe("rotated");
    expect(epochPackages(w.server, X, currentEpoch(w.server, X))).not.toContain(toHex(id(2)));
  });
});

describe("reconciliation (§7.1)", { timeout: 60_000 }, () => {
  test("a new roster Resource: registrations and keys; a second run proposes nothing", async () => {
    const w = await world(0);
    await pair(w, w.P, 2, "full");
    await pair(w, w.P, 3, "read");
    const Y = await hostResource(w.server, w.P);
    await addToRoster(w.P, w.I, Y.resource, Y.entry);
    const first = await reconcileDevices(w.P);
    const y = first.targets.find((t) => toHex(t.resource) === toHex(Y.resource));
    expect(y?.steps.map((s) => s.step.kind)).toEqual(["revoke", "revoke", "register", "register"]);
    expect(y?.steps.every((s) => s.state === "committed-own")).toBe(true);
    expect(epochPackages(w.server, Y.resource, 0n)).toEqual([toHex(id(2)), toHex(id(3))].sort());
    const second = await reconcileDevices(w.P);
    expect(second.targets.every((t) => t.steps.length === 0)).toBe(true);
    expect(second.targets.every((t) => t.keys === undefined || t.keys.sent.length === 0)).toBe(
      true,
    );
  });

  test("key bootstrap: a device whose approver sent no package is served by the next manager (F19)", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const A = await pair(w, w.P, 2, "full");
    // P approves B, but every package to B is lost.
    w.server.fault = (e) =>
      e.op === "key-package" && bytesEqual(parseKeyPackage(e.bytes).payload.recipient, id(3))
        ? "drop-request"
        : undefined;
    const lost = await pair(w, w.P, 3, "read").catch((e: Error) => e);
    expect(lost).toBeInstanceOf(Error);
    w.server.fault = () => undefined;
    const rec = await reconcileDevices(A);
    expect(rec.targets.flatMap((t) => t.keys?.sent.map((s) => s.recipient) ?? [])).toContain(
      toHex(id(3)),
    );
    expect(epochPackages(w.server, X, 0n)).toContain(toHex(id(3)));
    expect(principalRefOf(id(3))).toMatch(/^p:/);
  });
});
