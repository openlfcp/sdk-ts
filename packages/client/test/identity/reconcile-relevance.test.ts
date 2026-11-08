import { type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import {
  type ControlBody,
  DEVICE_KIND,
  decodeControlRecord,
  revocationOf,
  type Signer,
  signControlRecord,
} from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { readersAt } from "../../src/identity/context.js";
import { createPairingSession } from "../../src/identity/pairing.js";
import {
  keyRecipients,
  planRevocations,
  reconcileDevices,
  revocationRelevant,
} from "../../src/identity/reconcile.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { addToRoster, hostResource, pair, world } from "./world.js";

// IDENTITY-PROFILE-01 §7.1 steps 1 and 3 and §8.4 at mvp-0.4-baseline.4
// (finding 1 of LFCP-04-415): only relevant revocations are propagated, a
// refused one stays unpropagated, and nothing is registered in or sealed to
// a device that I has revoked.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const hex = (b: Uint8Array) => toHex(b);

async function commit(server: MemoryCoordinator, signer: Signer, X: ResourceId, body: ControlBody) {
  const chain = server.chain(X);
  const record = signControlRecord(
    { resourceId: X, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
    body,
    signer,
  );
  const channel = await server.network().connect(signer, URL);
  const answer = await channel.putControl(X, chain.state.head, record.bytes);
  channel.close();
  return answer;
}

const pairingDevicesOf = (server: MemoryCoordinator, I: ResourceId) =>
  [...server.chain(I).state.devices.entries()]
    .filter(([, d]) => d.kind === DEVICE_KIND.PAIRING)
    .map(([h]) => h);

describe("reconciliation propagates only relevant revocations (IDENTITY-PROFILE-01 §7.1 step 1)", {
  timeout: 120_000,
}, () => {
  test("routine pairing takes none of the root's 64 unbound pairs in a roster Resource", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const R = id(1);
    await pair(w, w.P, 3, "edit");
    await pair(w, w.P, 4, "read");
    const pairing = pairingDevicesOf(w.server, w.I);
    expect(pairing).toHaveLength(2);
    // Both pairing devices are revoked (consumed) in I.
    for (const j of pairing)
      expect(w.server.chain(w.I).state.revoked.has(`${hex(R)}:${j}`)).toBe(true);
    const run = await reconcileDevices(w.P);
    const x = run.targets.find((t) => hex(t.resource) === hex(X));
    expect(x?.status).toBe("done");
    expect(x?.steps.filter((s) => s.step.kind === "revoke")).toEqual([]);
    const state = w.server.chain(X).state;
    for (const j of pairing) expect(state.revoked.has(`${hex(R)}:${j}`)).toBe(false);
    expect(state.preemptive.get(hex(R)) ?? 0).toBe(0);
    // The personal devices are registered in X and keyed; a second run proposes nothing.
    for (const d of [3, 4]) expect(state.devices.get(hex(id(d)))?.registered).toBe(true);
    const again = await reconcileDevices(w.P);
    expect(again.targets.flatMap((t) => t.steps)).toEqual([]);
  });

  test("a refused revocation is reported, stays unpropagated, and is proposed again once the device is bound", async () => {
    const w = await world(0);
    const R = id(1);
    // DEV_3 is paired and revoked in I before X is on the roster: X never saw it.
    await pair(w, w.P, 3, "edit");
    const revoked = await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    expect(revoked.kind).toBe("revoked");
    const hosted = await hostResource(w.server, w.P);
    const X = hosted.resource;
    // X already holds 64 revoked pairs of R with an unbound device (W §17.5 rule 5).
    for (let i = 0; i < 64; i++) {
      const answer = await commit(w.server, w.P.installation.signer, X, {
        type: "DEVICE_REVOKE",
        root: R,
        device: id(100 + i),
        reason: 1n,
      });
      expect(answer.kind).toBe("ack");
    }
    expect(w.server.chain(X).state.preemptive.get(hex(R))).toBe(64);
    await addToRoster(w.P, w.I, X, hosted.entry);

    const first = await reconcileDevices(w.P);
    const x1 = first.targets.find((t) => hex(t.resource) === hex(X));
    expect(x1?.steps.map((s) => [s.step.kind, hex(s.step.device), s.state])).toEqual([
      ["revoke", hex(id(3)), "refused"],
    ]);
    expect(x1?.unpropagated?.map(hex)).toEqual([hex(id(3))]);
    // Never bound to lift the limit, and nothing sealed to it.
    expect(w.server.chain(X).state.devices.has(hex(id(3)))).toBe(false);
    expect(x1?.keys?.sent.some((p) => p.recipient === hex(id(3)))).toBe(false);

    // The residual risk the text names: DEV_3 registers itself in X with its old chain.
    const chain = w.server.chain(w.I).state.devices.get(hex(id(3)))?.chain;
    if (chain === null || chain === undefined) throw new Error("no chain in I");
    const self = await commit(w.server, party(3).signer, X, {
      type: "DEVICE_GRANT",
      root: R,
      chain,
    });
    expect(self.kind).toBe("ack");
    const X2 = w.server.chain(X);
    // Step 3 alone: a reader of X that I has revoked receives nothing.
    expect(readersAt(X2.state).some((r) => hex(r.principalId) === hex(id(3)))).toBe(true);
    expect(
      keyRecipients(w.server.chain(w.I), X2).some((r) => hex(r.principalId) === hex(id(3))),
    ).toBe(false);

    // The next run proposes it again: bound now, never limited, and exposing.
    const second = await reconcileDevices(w.P);
    const x2 = second.targets.find((t) => hex(t.resource) === hex(X));
    expect(x2?.steps.map((s) => [s.step.kind, hex(s.step.device), s.state])).toEqual([
      ["revoke", hex(id(3)), "committed-own"],
    ]);
    expect(x2?.unpropagated).toBeUndefined();
    expect(x2?.keys?.sent.some((p) => p.recipient === hex(id(3)))).toBe(false);
    expect(x2?.rotation?.status).toBe("rotated");
    const after = w.server.chain(X).state;
    expect(revocationOf(after, R, id(3))).toBeDefined();
    expect(after.preemptive.get(hex(R))).toBe(64);
  });
});

// Review LFCP-04-415f's independent checks of §7.1 steps 1 and 3 and §8.4.
describe("relevance, ordering and exclusions (review LFCP-04-415f)", { timeout: 120_000 }, () => {
  test("relevance: unknown, personal, service in and out of scope, pairing; any binding in X wins", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const target = w.server.chain(X).state;
    const bindings = [
      undefined,
      { kind: 0, scope: [] },
      { kind: 1, scope: [X] },
      { kind: 1, scope: [w.I] },
      { kind: 2, scope: [w.I] },
    ] as const;
    expect(bindings.map((b) => revocationRelevant(b as never, target, id(3)))).toEqual([
      true,
      true,
      true,
      false,
      false,
    ]);
    await pair(w, w.P, 3, "read");
    const bound = w.server.chain(X).state;
    expect(bindings.map((b) => revocationRelevant(b as never, bound, id(3)))).toEqual([
      true,
      true,
      true,
      true,
      true,
    ]);
  });

  test("a service device out of a Resource's scope spends no pair there; an unknown device is propagated", async () => {
    const w = await world(2);
    const [X, Y] = w.resources as [ResourceId, ResourceId];
    await pair(w, w.P, 3, "service", { kind: 1, scope: [X] });
    const r = await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    expect(r.kind === "revoked" && r.results.find((t) => hex(t.resource) === hex(Y))?.revoke).toBe(
      "not-relevant",
    );
    expect(w.server.chain(Y).state.preemptive.get(hex(id(1))) ?? 0).toBe(0);
    const u = await revokeDevice({ ...w.P, device: id(99), reason: 1n });
    expect(u.kind === "revoked" && u.results.map((t) => t.revoke)).toEqual([
      "revoked",
      "revoked",
      "revoked",
    ]);
  });

  test("bound devices first; a revoked device and a device it issued receive no key", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const A = await pair(w, w.P, 2, "full");
    await pair(w, A, 3, "read");
    w.server.down.add(hex(X));
    await revokeDevice({ ...w.P, device: id(99), reason: 1n });
    await revokeDevice({ ...w.P, device: id(2), reason: 1n });
    w.server.down.clear();
    const I = w.server.chain(w.I);
    const x = w.server.chain(X);
    expect(planRevocations(I, x).propose.map((p) => hex(p.device))).toEqual([
      hex(id(2)),
      hex(id(99)),
    ]);
    const recipients = keyRecipients(I, x).map((p) => hex(p.principalId));
    expect(recipients).not.toContain(hex(id(2)));
    expect(recipients).not.toContain(hex(id(3)));
  });
});

describe("a refused propagation is not repeated on an unchanged target (§7.1 step 1)", {
  timeout: 120_000,
}, () => {
  test("proposed again only once X's head moved; reported meanwhile without a CONTROL_PUT", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const R = id(1);
    await pair(w, w.P, 3, "read");
    // DEV_3 is revoked in I while X is unreachable, then X refuses its propagation.
    w.server.down.add(hex(X));
    await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    w.server.down.clear();
    // DEV_3 is bound in X: a refusal here is the reconciler's authority, injected.
    // Unbound pairs are what the memory is for: X forgets DEV_3's binding below.
    w.server.fault = (e) =>
      e.op === "control" && hex(e.resource) === hex(X)
        ? { nack: "AUTHORIZATION_FAILED" }
        : undefined;
    const puts = () =>
      w.server.uploads.filter((e) => e.op === "control" && hex(e.resource) === hex(X)).length;
    const x = (r: Awaited<ReturnType<typeof reconcileDevices>>) =>
      r.targets.find((t) => hex(t.resource) === hex(X));

    // The bound device's revocation is never limited: refused or not, it is proposed every run.
    const bound1 = await reconcileDevices({ ...w.P, only: [X], rotate: false });
    expect(x(bound1)?.unpropagated?.map(hex)).toEqual([hex(id(3))]);
    const sentBound = puts();
    await reconcileDevices({ ...w.P, only: [X], rotate: false });
    expect(puts()).toBe(sentBound + 1);

    // An unbound device: a fresh X where DEV_3 never registered.
    const hosted = await hostResource(w.server, w.P);
    const Y = hosted.resource;
    await addToRoster(w.P, w.I, Y, hosted.entry);
    w.server.fault = (e) => {
      if (e.op !== "control" || hex(e.resource) !== hex(Y)) return undefined;
      const b = decodeControlRecord(e.bytes).body;
      return b.type === "DEVICE_REVOKE" && hex(b.device) === hex(id(3))
        ? { nack: "AUTHORIZATION_FAILED" }
        : undefined;
    };
    const putsY = () =>
      w.server.uploads.filter((e) => e.op === "control" && hex(e.resource) === hex(Y)).length;
    const y = (r: Awaited<ReturnType<typeof reconcileDevices>>) =>
      r.targets.find((t) => hex(t.resource) === hex(Y));
    const first = await reconcileDevices({ ...w.P, only: [Y], rotate: false });
    expect(y(first)?.steps.map((s) => [s.step.kind, hex(s.step.device), s.state])).toEqual([
      ["revoke", hex(id(3)), "refused"],
    ]);
    expect(y(first)?.unpropagated?.map(hex)).toEqual([hex(id(3))]);
    const head = hex(w.server.chain(Y).state.head);
    const sent = putsY();

    // The same state of Y: reported, still unpropagated, nothing sent.
    const second = await reconcileDevices({ ...w.P, only: [Y], rotate: false });
    expect(hex(w.server.chain(Y).state.head)).toBe(head);
    expect(y(second)?.steps.map((s) => [s.step.kind, hex(s.step.device), s.state])).toEqual([
      ["revoke", hex(id(3)), "refused"],
    ]);
    expect(y(second)?.unpropagated?.map(hex)).toEqual([hex(id(3))]);
    expect(putsY()).toBe(sent);
    expect(w.server.chain(Y).state.devices.has(hex(id(3)))).toBe(false);

    // Y's state changes (another record): the pair is proposed again.
    const other = await commit(w.server, w.P.installation.signer, Y, {
      type: "DEVICE_REVOKE",
      root: R,
      device: id(200),
      reason: 1n,
    });
    expect(other.kind).toBe("ack");
    const third = await reconcileDevices({ ...w.P, only: [Y], rotate: false });
    expect(putsY()).toBe(sent + 2);
    expect(y(third)?.unpropagated?.map(hex)).toEqual([hex(id(3))]);

    // Y stops refusing: the next run on a changed state propagates it.
    w.server.fault = () => undefined;
    expect(
      (
        await commit(w.server, w.P.installation.signer, Y, {
          type: "DEVICE_REVOKE",
          root: R,
          device: id(201),
          reason: 1n,
        })
      ).kind,
    ).toBe("ack");
    const fourth = await reconcileDevices({ ...w.P, only: [Y], rotate: false });
    expect(y(fourth)?.unpropagated).toBeUndefined();
    expect(revocationOf(w.server.chain(Y).state, R, id(3))).toBeDefined();
  });
});

describe("§8.4: a revocation goes only where it is relevant", { timeout: 120_000 }, () => {
  test("revoking a pairing device does not touch a roster Resource where it is unbound", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const r = await revokeDevice({ ...w.P, device: s.pairingDevice, reason: 0n });
    if (r.kind !== "revoked") throw new Error(r.kind);
    expect(r.results.map((x) => [hex(x.resource), x.revoke])).toEqual([
      [hex(w.I), "revoked"],
      [hex(X), "not-relevant"],
    ]);
    expect(w.server.chain(X).state.revoked.size).toBe(0);
  });

  test("revoking a personal device not yet registered in a roster Resource still records it there", async () => {
    const w = await world(0);
    await pair(w, w.P, 3, "edit");
    const hosted = await hostResource(w.server, w.P);
    await addToRoster(w.P, w.I, hosted.resource, hosted.entry);
    const r = await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    if (r.kind !== "revoked") throw new Error(r.kind);
    expect(r.results.map((x) => [hex(x.resource), x.revoke])).toEqual([
      [hex(w.I), "revoked"],
      [hex(hosted.resource), "revoked"],
    ]);
  });
});
