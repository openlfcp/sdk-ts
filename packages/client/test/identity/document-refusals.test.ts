// A refused write of the Identity Resource's document is never a silent
// success (review of sdk-ts#16, P2): the flows rebuild a unit refused as
// stale on the current state (W §19.1), report any other refusal with an
// explicit result and keep their operation open, and a resumed operation
// writes the unit again.
import { bytesEqual, type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import { deviceFingerprint } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks, loadIdentityDocument, syncChain } from "../../src/identity/context.js";
import { principalRefOf } from "../../src/identity/document.js";
import { OperationJournal } from "../../src/identity/journal.js";
import {
  approvePairing,
  cancelPairing,
  createPairingSession,
  pairingRequests,
  resumeApproval,
} from "../../src/identity/pairing.js";
import { requestPairing } from "../../src/identity/pairing-request.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import type { MemoryCoordinator, UploadEvent } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { type Node, node, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;

/** `who`'s view of I's document, read from the coordinator. */
async function documentOf(who: Node, I: ResourceId) {
  const channel = await who.network.connect(who.installation.signer, URL);
  const chain = await syncChain(who.storage, channel, I);
  const doc = who.document(I, chain.state.owner.principalId);
  await loadIdentityDocument({ channel, chain, deks: await heldDeks(who.secrets, chain), doc });
  return doc;
}

/** A NACK with `code` for the next `times` Data Units `by` uploads to `resource`. */
function nackUnits(
  server: MemoryCoordinator,
  by: PrincipalId,
  resource: ResourceId,
  code: string,
  times = Number.POSITIVE_INFINITY,
) {
  let left = times;
  server.fault = (e: UploadEvent) => {
    if (
      e.op !== "data-unit" ||
      !bytesEqual(e.signer.descriptor.principalId, by) ||
      !bytesEqual(e.resource, resource) ||
      left <= 0
    )
      return undefined;
    left--;
    return { nack: code };
  };
}

/** A pairing session of P with device 2's request in it, reviewed by P. */
async function reviewed(w: Awaited<ReturnType<typeof world>>) {
  const s = await createPairingSession(w.P);
  if (s.kind !== "created") throw new Error(s.kind);
  const B = node(w.server, party(2));
  const req = await requestPairing({ ...B, link: s.link, label: "device 2", kind: 0 });
  if (req.kind !== "requested") throw new Error(req.kind);
  const [review] = await pairingRequests({ ...w.P, session: s.session });
  if (review === undefined) throw new Error("no request");
  return { session: s.session, review, key: principalRefOf(id(2)) };
}

describe("pairing approval: the document unit of §5.3 step 6", { timeout: 60_000 }, () => {
  test("refused as stale: written again on the current state, the approval complete", async () => {
    const w = await world(0);
    const { review, key } = await reviewed(w);
    nackUnits(w.server, id(1), w.I, "STALE_DATA_EPOCH", 1);
    const a = await approvePairing({ ...w.P, review, preset: "full" });
    w.server.fault = () => undefined;
    expect(a.kind).toBe("approved");
    const doc = await documentOf(w.P, w.I);
    expect(doc.devices().get(key)?.label).toBe("device 2");
    expect(doc.requests().has(key)).toBe(false);
  });

  test("refused otherwise: document-incomplete, the operation open; resumed, the unit is written", async () => {
    const w = await world(0);
    const { review, key } = await reviewed(w);
    nackUnits(w.server, id(1), w.I, "AUTHORIZATION_FAILED");
    const a = await approvePairing({ ...w.P, review, preset: "full" });
    w.server.fault = () => undefined;
    if (a.kind !== "document-incomplete") throw new Error(`approval: ${a.kind}`);
    expect(a.code).toBe("AUTHORIZATION_FAILED");
    // Phases 1 and 2 hold: the device is bound in I.
    expect(w.server.chain(w.I).state.devices.has(toHex(id(2)))).toBe(true);
    expect((await new OperationJournal(w.P.storage).load(a.operation)).status).toBe("open");
    expect((await documentOf(w.P, w.I)).devices().has(key)).toBe(false);

    const again = await resumeApproval(w.P, a.operation);
    expect(again.kind).toBe("approved");
    expect((await new OperationJournal(w.P.storage).load(a.operation)).status).toBe("done");
    const doc = await documentOf(w.P, w.I);
    expect(doc.devices().get(key)?.label).toBe("device 2");
    expect(doc.requests().has(key)).toBe(false);
  });
});

describe("pairing rejection: the unit that deletes the request (§5.3 step 4)", {
  timeout: 60_000,
}, () => {
  test("refused as stale: written again, the session cancelled", async () => {
    const w = await world(0);
    const { session, key } = await reviewed(w);
    nackUnits(w.server, id(1), w.I, "STALE_DATA_EPOCH", 1);
    const c = await cancelPairing({ ...w.P, session, reject: key });
    w.server.fault = () => undefined;
    expect(c.kind).toBe("cancelled");
    expect((await documentOf(w.P, w.I)).requests().has(key)).toBe(false);
    expect((await new OperationJournal(w.P.storage).load(session)).status).toBe("abandoned");
  });

  test("refused otherwise: document-incomplete, the session open; cancelled again, the request goes", async () => {
    const w = await world(0);
    const { session, key } = await reviewed(w);
    nackUnits(w.server, id(1), w.I, "AUTHORIZATION_FAILED");
    const c = await cancelPairing({ ...w.P, session, reject: key });
    w.server.fault = () => undefined;
    if (c.kind !== "document-incomplete") throw new Error(`cancel: ${c.kind}`);
    expect(c.code).toBe("AUTHORIZATION_FAILED");
    expect((await new OperationJournal(w.P.storage).load(session)).status).toBe("open");
    expect((await documentOf(w.P, w.I)).requests().has(key)).toBe(true);

    expect((await cancelPairing({ ...w.P, session, reject: key })).kind).toBe("cancelled");
    expect((await documentOf(w.P, w.I)).requests().has(key)).toBe(false);
    expect((await new OperationJournal(w.P.storage).load(session)).status).toBe("abandoned");
  });
});

describe("reconciliation: the display unit of §7.1 step 4", { timeout: 60_000 }, () => {
  /** Device 2 approved in I's chain, its device entry never written. */
  async function withoutEntry() {
    const w = await world(0);
    const { review, key } = await reviewed(w);
    nackUnits(w.server, id(1), w.I, "AUTHORIZATION_FAILED");
    const a = await approvePairing({ ...w.P, review, preset: "full" });
    w.server.fault = () => undefined;
    if (a.kind !== "document-incomplete") throw new Error(`approval: ${a.kind}`);
    return { w, key };
  }

  test("refused as stale: written again on the current state of I", async () => {
    const { w, key } = await withoutEntry();
    nackUnits(w.server, id(1), w.I, "STALE_DATA_EPOCH", 1);
    const r = await reconcileDevices({ ...w.P, only: [w.I] });
    w.server.fault = () => undefined;
    expect(r.document).toEqual({ state: "committed-own" });
    expect((await documentOf(w.P, w.I)).devices().get(key)?.label).toBe(deviceFingerprint(id(2)));
    expect((await new OperationJournal(w.P.storage).load(r.operation)).status).toBe("done");
  });

  test("refused otherwise: reported, the operation open; the next run writes the entry", async () => {
    const { w, key } = await withoutEntry();
    nackUnits(w.server, id(1), w.I, "AUTHORIZATION_FAILED");
    const r = await reconcileDevices({ ...w.P, only: [w.I] });
    w.server.fault = () => undefined;
    expect(r.document).toEqual({ state: "refused", code: "AUTHORIZATION_FAILED" });
    expect((await new OperationJournal(w.P.storage).load(r.operation)).status).toBe("open");
    expect((await documentOf(w.P, w.I)).devices().has(key)).toBe(false);

    const again = await reconcileDevices({ ...w.P, only: [w.I] });
    expect(again.document).toEqual({ state: "committed-own" });
    expect((await documentOf(w.P, w.I)).devices().has(key)).toBe(true);
  });
});
