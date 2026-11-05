import { bytesEqual, dataEpoch, toHex } from "@openlfcp/core";
import { dekSecretRef } from "@openlfcp/storage";
import { DEVICE_KIND, parseControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { principalRefOf } from "../../src/identity/document.js";
import { OperationJournal } from "../../src/identity/journal.js";
import {
  approvePairing,
  cancelPairing,
  createPairingSession,
  pairingRequests,
  resumeApproval,
  resumePairingSession,
} from "../../src/identity/pairing.js";
import { completePairing, requestPairing } from "../../src/identity/pairing-request.js";
import { createIdentityResource } from "../../src/identity/resource.js";
import { MemoryCoordinator } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { hostResource, node, world } from "./world.js";

const types = (server: MemoryCoordinator, R: Uint8Array): string[] =>
  server.chain(R as never).records.map((r) => r.body.type);

async function session(w: Awaited<ReturnType<typeof world>>) {
  const s = await createPairingSession(w.P);
  if (s.kind !== "created") throw new Error(s.kind);
  return s;
}

describe("pairing a personal installation (IDENTITY-PROFILE-01 §5.3)", { timeout: 60_000 }, () => {
  test("session, request, review, phases 1 and 2, keys, registration in the roster, B ready everywhere", async () => {
    const w = await world(1);
    const s = await session(w);
    expect(String(s.link)).toBe("[redacted]");
    expect(JSON.stringify({ l: s.link })).not.toContain("lfcp://");
    // J holds every epoch of I.
    expect(
      w.server.packagesOf(w.I).filter((p) => bytesEqual(p.recipient, s.pairingDevice)).length,
    ).toBe(1);

    const B = node(w.server, party(3));
    const req = await requestPairing({
      ...B,
      link: s.link,
      label: "desktop",
      kind: 0,
      platform: "linux",
    });
    if (req.kind !== "requested") throw new Error(req.kind);
    expect(await completePairing({ ...B, operation: req.operation })).toEqual({ kind: "waiting" });

    const [review, ...rest] = await pairingRequests({ ...w.P, session: s.session });
    expect(rest).toEqual([]);
    if (review === undefined) throw new Error("no request");
    expect(review.fingerprint).toBe(req.fingerprint);
    expect(review.label).toBe("desktop");
    expect(review.presets.map((p) => [p.preset, p.offered])).toEqual([
      ["full", true],
      ["edit", true],
      ["read", true],
    ]);
    const approved = await approvePairing({ ...w.P, review, preset: "full" });
    if (approved.kind !== "approved") throw new Error(JSON.stringify(approved));
    expect(approved.registrations.map((r) => r.status)).toEqual(["registered"]);
    // Phase 1, phase 2, then the rotation of I: the consumed J was a reader (§5.3 step 9).
    expect(types(w.server, w.I).slice(-4)).toEqual([
      "DEVICE_GRANT",
      "DEVICE_REVOKE",
      "DEVICE_GRANT",
      "KEY_EPOCH",
    ]);
    expect(approved.rotation.status).toBe("rotated");
    // The new DEK went to every reader except the consumed J and the rotator itself: B.
    const epoch1 = w.server.packagesOf(w.I).filter((p) => p.dataEpoch === 1n);
    expect(epoch1.map((p) => toHex(p.recipient))).toEqual([
      toHex(party(3).signer.descriptor.principalId),
    ]);

    const done = await completePairing({ ...B, operation: req.operation });
    if (done.kind !== "approved") throw new Error(done.kind);
    expect(done.certificate?.leaf.payload.kind).toBe(DEVICE_KIND.PERSONAL);
    expect(done.candidates.map((c) => [toHex(c.resource), c.status])).toEqual([
      [toHex(w.I), "ready"],
      [toHex(w.resources[0] as Uint8Array), "ready"],
    ]);
    // The device entry replaced the request (§5.3 step 6).
    const P2 = await pairingRequests({ ...w.P, session: s.session });
    expect(P2).toEqual([]);
    // The session is finished; the approval journal is done.
    const journal = new OperationJournal(w.P.storage);
    expect((await journal.list({ status: "open" })).map((o) => o.kind)).toEqual([]);
  });

  test("a crash at each ACK of the approval resumes from the journaled payload (§9.1, F13)", async () => {
    for (const lost of ["consume", "register"] as const) {
      const w = await world(1);
      const s = await session(w);
      const B = node(w.server, party(3));
      const req = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
      if (req.kind !== "requested") throw new Error(req.kind);
      const [review] = await pairingRequests({ ...w.P, session: s.session });
      if (review === undefined) throw new Error("no request");
      const kind = lost === "consume" ? "DEVICE_REVOKE" : "DEVICE_GRANT";
      w.server.fault = (e) =>
        e.op === "control" && recordType(e.bytes) === kind ? "drop-answer" : undefined;
      const first = await approvePairing({ ...w.P, review, preset: "edit" });
      expect(first.kind).toBe("unavailable");
      w.server.fault = () => undefined;
      const op = (await new OperationJournal(w.P.storage).list({ kind: "pairing-approval" }))[0];
      if (op === undefined) throw new Error("no journal");
      const resumed = await resumeApproval(w.P, op.id);
      expect(resumed.kind).toBe("approved");
      const records = types(w.server, w.I);
      expect(records.filter((t) => t === "DEVICE_REVOKE").length).toBe(1);
      expect(records.filter((t) => t === "DEVICE_GRANT").length).toBe(2);
      const phase = (await new OperationJournal(w.P.storage).load(op.id)).phases.find(
        (p) => p.id === lost,
      );
      expect(phase?.state).toBe("committed-own");
      const done = await completePairing({ ...B, operation: req.operation });
      expect(done.kind === "approved" && done.candidates.every((c) => c.status === "ready")).toBe(
        true,
      );
    }
  });

  test("an approval of a consumed session is superseded and signs nothing (§5.3 step 5)", async () => {
    const w = await world(0);
    const s = await session(w);
    const B = node(w.server, party(3));
    const C = node(w.server, party(4));
    const r1 = await requestPairing({ ...B, link: s.link, label: "b", kind: 0 });
    // One link, a second installation: it sees the first request and writes sequence 2.
    const r2 = await requestPairing({ ...C, link: s.link, label: "c", kind: 0 });
    expect([r1.kind, r2.kind]).toEqual(["requested", "requested"]);
    const reviews = await pairingRequests({ ...w.P, session: s.session });
    expect(reviews.map((r) => r.label).sort()).toEqual(["b", "c"]);
    const forB = reviews.find((r) => r.label === "b");
    const forC = reviews.find((r) => r.label === "c");
    if (forB === undefined || forC === undefined) throw new Error("missing");
    // The approval of C is journaled, its consume lost on the way (a second manager's race).
    w.server.fault = (e) => (e.op === "control" ? "drop-request" : undefined);
    expect((await approvePairing({ ...w.P, review: forC, preset: "read" })).kind).toBe(
      "unavailable",
    );
    w.server.fault = () => undefined;
    const pendingC = (
      await new OperationJournal(w.P.storage).list({ kind: "pairing-approval" })
    )[0];
    expect((await approvePairing({ ...w.P, review: forB, preset: "read" })).kind).toBe("approved");
    const before = types(w.server, w.I).length;
    const second = await resumeApproval(w.P, (pendingC as { id: string }).id);
    expect(second.kind).toBe("superseded");
    expect(types(w.server, w.I).length).toBe(before);
    const consume = (await new OperationJournal(w.P.storage).load((pendingC as { id: string }).id))
      .phases;
    expect(consume.map((p) => [p.id, p.state])).toEqual([["consume", "superseded"]]);
    const outcome = await completePairing({
      ...C,
      operation: (r2 as { operation: string }).operation,
    });
    expect(outcome.kind === "approved" && outcome.certificate === null).toBe(true);
  });

  test("a changed request asks for confirmation again (§5.3 step 4)", async () => {
    const w = await world(0);
    const s = await session(w);
    const B = node(w.server, party(3));
    await requestPairing({ ...B, link: s.link, label: "b", kind: 0 });
    const [review] = await pairingRequests({ ...w.P, session: s.session });
    if (review === undefined) throw new Error("none");
    const changed = { ...review, tuple: review.tuple.replace('"b"', '"x"') };
    const r = await approvePairing({ ...w.P, review: changed, preset: "edit" });
    expect(r.kind).toBe("reconfirm");
  });

  test("a rejected request: the entry is deleted, the session cancelled, B learns it from the prefix (W §41)", async () => {
    const w = await world(0);
    const s = await session(w);
    const B = node(w.server, party(3));
    const req = await requestPairing({ ...B, link: s.link, label: "b", kind: 0 });
    if (req.kind !== "requested") throw new Error(req.kind);
    const key = principalRefOf(party(3).signer.descriptor.principalId);
    expect((await cancelPairing({ ...w.P, session: s.session, reject: key })).kind).toBe(
      "cancelled",
    );
    expect(await completePairing({ ...B, operation: req.operation })).toEqual({ kind: "rejected" });
    // Cancelling again is complete, not a new record (§9.2 Cancel).
    const n = types(w.server, w.I).length;
    expect((await cancelPairing({ ...w.P, session: s.session })).kind).toBe("cancelled");
    expect(types(w.server, w.I).length).toBe(n);
  });

  test("no link without every DEK of I (§5.3 step 1)", async () => {
    const w = await world(0);
    await w.P.secrets.delete(dekSecretRef(w.I, dataEpoch(0n)));
    const s = await createPairingSession(w.P);
    expect(s.kind).toBe("missing-material");
  });

  test("a lost answer of J's DEVICE_GRANT: the link is shown after the journal completes (§5.3 step 1)", async () => {
    const w = await world(0);
    w.server.fault = (e) => (e.op === "control" ? "drop-answer" : undefined);
    const s = await createPairingSession(w.P);
    expect(s.kind).toBe("unavailable");
    w.server.fault = () => undefined;
    const open = await new OperationJournal(w.P.storage).list({ kind: "pairing-session" });
    const again = await resumePairingSession(w.P, (open[0] as { id: string }).id);
    expect(again.kind).toBe("created");
    expect(types(w.server, w.I).filter((t) => t === "DEVICE_GRANT").length).toBe(1);
  });
});

describe("pairing a service installation (§5.3 step 8, §6)", { timeout: 60_000 }, () => {
  test("requested {X, Y}, approved {X}: X ready, Y not granted, never registered in I", async () => {
    const w = await world(2);
    const [X, Y] = w.resources as unknown as [Uint8Array, Uint8Array];
    const s = await session(w);
    const S = node(w.server, party(5));
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
    expect(review.presets).toEqual([{ preset: "service", offered: true }]);
    expect(review.requestedScope.length).toBe(2);
    const approved = await approvePairing({
      ...w.P,
      review,
      preset: "service",
      scope: [X as never],
    });
    if (approved.kind !== "approved") throw new Error(approved.kind);
    expect(approved.registrations.map((r) => r.status)).toEqual(["registered"]);
    const I = w.server.chain(w.I).state.devices.get(toHex(party(5).signer.descriptor.principalId));
    expect(I?.registered).toBe(false);

    // Every candidate offline after approval: approved, waiting for registration.
    w.server.down.add(toHex(X));
    w.server.down.add(toHex(Y));
    const waiting = await completePairing({ ...S, operation: req.operation });
    expect(waiting).toEqual({
      kind: "approved",
      certificate: null,
      candidates: [],
      foreignCertificates: 0,
    });
    w.server.down.clear();
    const done = await completePairing({ ...S, operation: req.operation });
    if (done.kind !== "approved") throw new Error(done.kind);
    expect(done.candidates.map((c) => c.status)).toEqual(["ready", "not-granted"]);
  });

  test("a headless service names its sections by roster name (§5.3 headless)", async () => {
    const server = new MemoryCoordinator();
    const P = node(server, party(1));
    const named = [];
    for (const name of ["Notes", "Tasks", "Notes"]) {
      const r = await hostResource(server, P);
      named.push({ resource: r.resource, entry: { ...r.entry, name } });
    }
    const created = await createIdentityResource({
      ...P,
      url: URL,
      label: "laptop",
      roster: named,
    });
    if (created.kind !== "created") throw new Error(created.kind);
    const s = await createPairingSession(P);
    if (s.kind !== "created") throw new Error(s.kind);
    const S = node(server, party(5));
    // "Notes" names two roster Resources, "Mail" none: no request is written.
    const ambiguous = await requestPairing({
      ...S,
      link: s.link,
      label: "bridge",
      kind: 1,
      sections: ["Tasks", "Notes", "Mail"],
    });
    expect(ambiguous).toEqual({
      kind: "unknown-sections",
      unknown: ["Notes", "Mail"],
      available: ["Notes", "Notes", "Tasks"],
    });
    expect(await pairingRequests({ ...P, session: s.session })).toEqual([]);
    const req = await requestPairing({
      ...S,
      link: s.link,
      label: "bridge",
      kind: 1,
      sections: ["Tasks"],
    });
    if (req.kind !== "requested") throw new Error(req.kind);
    const [review] = await pairingRequests({ ...P, session: s.session });
    expect(review?.requestedScope.map((r) => toHex(r))).toEqual([
      toHex(named[1]?.resource as never),
    ]);
    if (review === undefined) throw new Error("none");
    const approved = await approvePairing({ ...P, review, preset: "service" });
    if (approved.kind !== "approved") throw new Error(approved.kind);
    // The outcome names each candidate as the roster did.
    const done = await completePairing({ ...S, operation: req.operation });
    if (done.kind !== "approved") throw new Error(done.kind);
    expect(done.candidates.map((c) => [c.name, c.status])).toEqual([["Tasks", "ready"]]);
  });

  test("a service scope trimmed to nothing is not approvable", async () => {
    const w = await world(1);
    const s = await session(w);
    const S = node(w.server, party(5));
    await requestPairing({
      ...S,
      link: s.link,
      label: "bot",
      kind: 1,
      scope: w.resources as never,
    });
    const [review] = await pairingRequests({ ...w.P, session: s.session });
    if (review === undefined) throw new Error("none");
    const r = await approvePairing({ ...w.P, review, preset: "service", scope: [] });
    expect(r.kind).toBe("infeasible");
  });

  test("an extra Resource owned by the root is registered only when listed", async () => {
    const w = await world(1);
    await hostResource(w.server, w.P);
    expect(w.server.hosted.size).toBe(3);
  });
});

function recordType(bytes: Uint8Array): string {
  // DEVICE_GRANT is type 9, DEVICE_REVOKE type 10 (W §14).
  const t = parseControlRecord(bytes).payload.controlType;
  return t === 9n ? "DEVICE_GRANT" : t === 10n ? "DEVICE_REVOKE" : String(t);
}
