import { toHex } from "@openlfcp/core";
import { parseDataUnit, rotateEpoch } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { deliverKeys, readersAt, storeDek, syncChain } from "../../src/identity/context.js";
import { PackageLedger } from "../../src/identity/journal.js";
import {
  cancelPairing,
  createPairingSession,
  pairingRequests,
} from "../../src/identity/pairing.js";
import { completePairing, requestPairing } from "../../src/identity/pairing-request.js";
import { party, URL } from "./support.js";
import { node, world } from "./world.js";

describe("a pairing request after a restart (IDENTITY-PROFILE-01 §5.3 step 3, §9.1)", {
  timeout: 60_000,
}, () => {
  test("a request lost on the way is sent from the journal by completePairing (11.1)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const B = node(w.server, party(3));
    w.server.fault = (e) => (e.op === "data-unit" ? "drop-request" : undefined);
    const req = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    expect(req.kind).toBe("unavailable");
    w.server.fault = () => undefined;
    const operation = (req as { operation?: string }).operation;
    if (operation === undefined) throw new Error("no operation");
    expect(await completePairing({ ...B, operation })).toEqual({ kind: "waiting" });
    const reviews = await pairingRequests({ ...w.P, session: s.session });
    expect(reviews.map((r) => r.label)).toEqual(["phone"]);
    // The resent unit is the journaled one: one byte string for J's sequence 1.
    const sent = w.server.uploads.filter(
      (u) =>
        u.op === "data-unit" &&
        toHex(parseDataUnit(u.bytes).payload.actor) === toHex(s.pairingDevice),
    );
    expect(new Set(sent.map((u) => toHex(u.bytes))).size).toBe(1);
    // Asking again resumes the same operation instead of writing a second request.
    const again = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    expect(again.kind === "requested" && again.operation).toBe(operation);
  });

  test("a request lost before I rotates is written again in the new epoch (11b.1)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const B = node(w.server, party(3));
    w.server.fault = (e) => (e.op === "data-unit" ? "drop-request" : undefined);
    const req = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    w.server.fault = () => undefined;
    const operation = (req as { operation?: string }).operation as string;
    // The root rotates I and seals the new epoch to its readers, J included.
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    const chain = await syncChain(w.P.storage, channel, w.I);
    // The closing epoch's frontier covers the root's units 1 and 2.
    const frontier = [
      { principalId: party(1).signer.descriptor.principalId, contiguous: 2n, extras: [] },
    ];
    const r = rotateEpoch(chain.state, w.P.installation.signer, {
      reason: 2n,
      finalFrontier: frontier,
    });
    expect((await channel.putControl(w.I, chain.state.head, r.bytes)).kind).toBe("ack");
    const after = await syncChain(w.P.storage, channel, w.I);
    await storeDek(w.P.storage, w.P.secrets, after, r.epoch, r.dek);
    await deliverKeys({
      channel,
      ledger: new PackageLedger(w.P.storage),
      chain: after,
      sender: w.P.installation.signer,
      recipients: readersAt(after.state),
      deks: new Map([[String(r.epoch), r.dek]]),
    });
    expect(await completePairing({ ...B, operation })).toEqual({ kind: "waiting" });
    const reviews = await pairingRequests({ ...w.P, session: s.session });
    expect(reviews.map((x) => x.label)).toEqual(["phone"]);
    const mine = w.server.unitsOf(w.I).filter((u) => toHex(u.actor) === toHex(s.pairingDevice));
    expect(mine.map((u) => [u.actorSeq, u.dataEpoch])).toEqual([[2n, r.epoch]]);
  });

  test("a request lost before the session is cancelled ends rejected (11b.1)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const B = node(w.server, party(3));
    w.server.fault = (e) => (e.op === "data-unit" ? "drop-request" : undefined);
    const req = await requestPairing({ ...B, link: s.link, label: "phone", kind: 0 });
    w.server.fault = () => undefined;
    expect((await cancelPairing({ ...w.P, session: s.session })).kind).toBe("cancelled");
    // The coordinator now refuses the request unit: the refusal must not hide the result.
    w.server.fault = (e) => (e.op === "data-unit" ? { nack: "AUTHORIZATION_FAILED" } : undefined);
    const operation = (req as { operation?: string }).operation as string;
    expect(await completePairing({ ...B, operation })).toEqual({ kind: "rejected" });
  });
});
