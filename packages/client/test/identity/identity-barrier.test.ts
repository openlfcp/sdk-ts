import { toHex } from "@openlfcp/core";
import { decodeControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { deliverKeys, heldDeks, storeDek, syncChain } from "../../src/identity/context.js";
import { leafPayload, registerDevice, signChain } from "../../src/identity/devices.js";
import { OperationJournal, PackageLedger } from "../../src/identity/journal.js";
import { createPairingSession, resumePairingSession } from "../../src/identity/pairing.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import { party, URL } from "./support.js";
import { node, world } from "./world.js";

// LFCP-WIRE-01 §37 (review LFCP-04-415f; F18_barrier #6): a client proposes
// no DEVICE_GRANT or DEVICE_REVOKE, and uploads no Key Package authorized
// only by the same-root rule, to a server whose READY lacks identity-01; it
// reports the Resource as hosted on a server without identity support.

/** A managing device of the root in I with 12 and without 6: its packages are same-root only. */
async function managerWithout6() {
  const w = await world(0);
  const A = node(w.server, party(2));
  const chain = signChain(
    w.server.chain(w.I).state,
    w.P.installation.signer,
    leafPayload(
      party(1).signer.descriptor.principalId,
      A.installation.signer.descriptor,
      0,
      [1n, 2n, 12n],
      [],
    ),
  );
  const reg = await registerDevice({ ...w.P, chain, targets: [{ resource: w.I, url: URL }] });
  expect(reg.results[0]?.status).toBe("registered");
  const I = w.server.chain(w.I);
  for (const [e, dek] of await heldDeks(w.P.secrets, I))
    await storeDek(A.storage, A.secrets, I, BigInt(e) as never, dek);
  return { w, A };
}

describe("no identity record or same-root package without identity-01 (LFCP-WIRE-01 §37)", {
  timeout: 120_000,
}, () => {
  test("createPairingSession on a server without identity-01 sends nothing and says so", async () => {
    const { w, A } = await managerWithout6();
    w.server.extensions = [];
    const before = w.server.uploads.length;
    const out = await createPairingSession({ ...A, identity: { resource: w.I, url: URL } });
    expect(out.kind).toBe("unsupported");
    expect(out.kind === "unsupported" && out.reason).toMatch(/without identity support/);
    expect(w.server.uploads.slice(before)).toEqual([]);
  });

  test("a session journaled before the server dropped identity-01 is not resumed there", async () => {
    const { w, A } = await managerWithout6();
    w.server.fault = (e) => (e.op === "control" ? "drop-request" : undefined);
    const lost = await createPairingSession({ ...A, identity: { resource: w.I, url: URL } });
    expect(lost.kind).toBe("unavailable");
    w.server.fault = () => undefined;
    w.server.extensions = [];
    const before = w.server.uploads.length;
    const [op] = await new OperationJournal(A.storage).list({ kind: "pairing-session" });
    const session = op?.id;
    if (session === undefined) throw new Error("no journaled session");
    const out = await resumePairingSession(
      { ...A, identity: { resource: w.I, url: URL } },
      session,
    );
    expect(out.kind).toBe("unsupported");
    expect(w.server.uploads.slice(before)).toEqual([]);
  });

  test("deliverKeys skips same-root-only packages without identity-01; key/distribute still sends", async () => {
    const { w, A } = await managerWithout6();
    w.server.extensions = [];
    const channel = await w.server.network().connect(A.installation.signer, URL);
    const I = await syncChain(A.storage, channel, w.I);
    const deks = await heldDeks(A.secrets, I);
    const before = w.server.uploads.length;
    const root = I.state.owner;
    const r = await deliverKeys({
      channel,
      ledger: new PackageLedger(A.storage),
      chain: I,
      sender: A.installation.signer,
      recipients: [root],
      deks,
    });
    expect(r.sent).toEqual([]);
    expect(r.skipped).toEqual([
      { recipient: toHex(root.principalId), reason: "IDENTITY_UNSUPPORTED" },
    ]);
    expect(w.server.uploads.slice(before)).toEqual([]);
    // The root holds key/distribute in its own Resource: its package is not same-root only.
    const rootChannel = await w.server.network().connect(w.P.installation.signer, URL);
    const fromRoot = await deliverKeys({
      channel: rootChannel,
      ledger: new PackageLedger(w.P.storage),
      chain: await syncChain(w.P.storage, rootChannel, w.I),
      sender: w.P.installation.signer,
      recipients: [A.installation.signer.descriptor],
      deks,
      // Sent again even though the registration delivered it.
      resend: new Map([
        [toHex(A.installation.signer.descriptor.principalId), new Set(deks.keys())],
      ]),
    });
    expect(fromRoot.skipped).toEqual([]);
    expect(fromRoot.sent.length).toBeGreaterThan(0);
  });

  test("no DEVICE_REVOKE is proposed to a server without identity-01 (any flow, runControlPhase)", async () => {
    const w = await world(0);
    w.server.extensions = [];
    const before = w.server.uploads.length;
    const r = await revokeDevice({
      ...w.P,
      device: party(99).signer.descriptor.principalId,
      reason: 1n,
    });
    expect(r.kind === "revoked" && r.results.map((x) => x.revoke)).toEqual(["refused"]);
    expect(w.server.uploads.slice(before)).toEqual([]);
  });

  // Review LFCP-04-415h finding 1: the barrier covers journaled bytes, not only rebuilt ones.
  test("a DEVICE_REVOKE journaled before the server dropped identity-01 is not sent again", async () => {
    const w = await world(0);
    const device = party(99).signer.descriptor.principalId;
    w.server.fault = (e) => (e.op === "control" ? "drop-request" : undefined);
    const first = await revokeDevice({ ...w.P, device, reason: 1n });
    expect(first.kind).toBe("unavailable");
    const journal = new OperationJournal(w.P.storage);
    const [op] = await journal.list({ kind: "revoke-device" });
    if (op === undefined) throw new Error("no journaled revocation");
    const head = toHex(w.server.chain(w.I).state.head);
    // The resumed phase would take the journaled-bytes branch: same bytes, same head.
    expect(op.phases.some((p) => p.bytes !== undefined && p.expectedHead === head)).toBe(true);
    w.server.fault = () => undefined;
    w.server.extensions = [];
    const before = w.server.uploads.length;
    const r = await revokeDevice({
      ...w.P,
      device,
      reason: 1n,
      operation: op.id,
    });
    const sent = w.server.uploads
      .slice(before)
      .filter((e) => e.op === "control")
      .map((e) => decodeControlRecord(e.bytes).body.type);
    expect(sent).toEqual([]);
    expect(r.kind === "revoked" && r.results[0]?.revoke).toBe("refused");
    const phase = (await journal.load(op.id)).phases.find((p) => p.kind === "revoke");
    expect(phase?.code).toBe("IDENTITY_UNSUPPORTED");
  });
});
