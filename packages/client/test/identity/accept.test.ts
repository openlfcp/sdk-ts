import { bytesEqual, dataEpoch, type PrincipalId, toHex } from "@openlfcp/core";
import { InvitationSecret } from "@openlfcp/crypto";
import {
  assembleInviteUri,
  invitationPrincipal,
  parseControlRecord,
  sealKeyPackage,
  signControlRecord,
} from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { acceptInvitationAsDevice, createResourceAsDevice } from "../../src/identity/accept.js";
import { fetchDeks, loadIdentityDocument, syncChain } from "../../src/identity/context.js";
import { resourceRef } from "../../src/identity/document.js";
import { revocationStatus } from "../../src/identity/proof.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import { party, URL } from "./support.js";
import { hostResource, type Node, node, pair, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;

/** Q invites someone to its Resource Z: a one-time invitation grant, its package and the link. */
async function invite(w: Awaited<ReturnType<typeof world>>, Q: Node) {
  const Z = await hostResource(w.server, Q);
  const secret = InvitationSecret.generate();
  const invitee = invitationPrincipal(secret);
  const chain = w.server.chain(Z.resource);
  const grant = signControlRecord(
    { resourceId: Z.resource, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
    {
      type: "CAPABILITY_GRANT",
      subject: invitee,
      abilities: [1n, 2n, 11n],
      delegable: [],
      claimLimit: 1n,
    },
    Q.installation.signer,
  );
  const ch = await Q.network.connect(Q.installation.signer, URL);
  expect((await ch.putControl(Z.resource, chain.state.head, grant.bytes)).kind).toBe("ack");
  const kp = await sealKeyPackage({
    resourceId: Z.resource,
    epoch: dataEpoch(0n),
    controlHead: grant.recordId,
    recipient: invitee,
    dek: Z.dek,
    signer: Q.installation.signer,
  });
  expect((await ch.putKeyPackage(Z.resource, kp.bytes)).kind).toBe("ack");
  const link = assembleInviteUri({
    resourceId: Z.resource,
    endpoints: [URL],
    grantId: grant.recordId,
    secret,
  });
  return { Z: Z.resource, link };
}

const claims = (w: Awaited<ReturnType<typeof world>>, Z: Uint8Array) =>
  w.server.chain(Z as never).records.filter((r) => r.body.type === "CAPABILITY_CLAIM");

describe("an invitation accepted by a device (IDENTITY-PROFILE-01 §7.2, F07)", {
  timeout: 60_000,
}, () => {
  test("the claim names the root; the device registers itself, keys the root and its sibling, lists the Resource", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const B = await pair(w, w.P, 3, "full");
    const Q = node(w.server, party(7));
    const { Z, link } = await invite(w, Q);
    const r = await acceptInvitationAsDevice({ ...B, link, name: "Shared notes" });
    if (r.kind !== "claimed") throw new Error(JSON.stringify(r));
    const [claim] = claims(w, Z);
    expect(claim?.body.type === "CAPABILITY_CLAIM" && toHex(claim.body.claimant.principalId)).toBe(
      toHex(id(1)),
    );
    const X = w.server.chain(Z as never).state;
    expect(X.devices.get(toHex(id(3)))?.registered).toBe(true);
    expect(X.devices.get(toHex(id(2)))?.registered).toBe(true);
    expect(r.rootKeys.sent.map((s) => s.recipient)).toEqual([toHex(id(1))]);
    expect(r.siblings.map((s) => s.status)).toEqual(["registered"]);
    expect(r.roster).toBe(true);
    // The root opens Z and reads it from the package (F07 step 5).
    const deks = await fetchDeks(
      w.P.storage,
      w.P.secrets,
      await w.P.network.connect(w.P.installation.signer, URL),
      w.server.chain(Z as never),
      w.P.installation,
    );
    expect(deks.has("0")).toBe(true);
    // The roster carries Z for the human's other installations.
    const channel = await A.network.connect(A.installation.signer, URL);
    const chainI = await syncChain(A.storage, channel, w.I);
    const doc = A.document(w.I, id(1));
    await loadIdentityDocument({
      channel,
      chain: chainI,
      deks: await fetchDeks(A.storage, A.secrets, channel, chainI, A.installation),
      doc,
    });
    expect(doc.roster().get(resourceRef(Z as never))?.name).toBe("Shared notes");
  });

  test("a Read device leaves the invitation unclaimed", async () => {
    const w = await world(0);
    const R3 = await pair(w, w.P, 3, "read");
    const { Z, link } = await invite(w, node(w.server, party(7)));
    expect((await acceptInvitationAsDevice({ ...R3, link })).kind).toBe("needs-writer");
    expect(claims(w, Z)).toEqual([]);
  });

  test("a lost answer of the self-registration resumes without a second claim", async () => {
    const w = await world(0);
    const B = await pair(w, w.P, 3, "edit");
    const { Z, link } = await invite(w, node(w.server, party(7)));
    w.server.fault = (e) =>
      e.op === "control" && parseControlRecord(e.bytes).payload.controlType === 9n
        ? "drop-answer"
        : undefined;
    const first = await acceptInvitationAsDevice({ ...B, link });
    expect(first.kind).toBe("unavailable");
    w.server.fault = () => undefined;
    const again = await acceptInvitationAsDevice({
      ...B,
      link,
      operation: (first as { operation: string }).operation,
    });
    expect(again.kind).toBe("claimed");
    expect(claims(w, Z).length).toBe(1);
    expect(
      w.server.chain(Z as never).records.filter((r) => r.body.type === "DEVICE_GRANT").length,
    ).toBe(1);
    // An Edit device does not register its siblings (no 12): reconciliation does.
    expect(again.kind === "claimed" && again.siblings).toEqual([]);
  });

  test("the root accepts as today, then registers and keys its devices", async () => {
    const w = await world(0);
    await pair(w, w.P, 2, "full");
    const { Z, link } = await invite(w, node(w.server, party(7)));
    const r = await acceptInvitationAsDevice({ ...w.P, link });
    if (r.kind !== "claimed") throw new Error(r.kind);
    expect(r.siblings.map((s) => s.status)).toEqual(["registered"]);
    expect(w.server.chain(Z as never).state.devices.get(toHex(id(2)))?.registered).toBe(true);
  });
});

describe("a Resource created from a device (§7.3)", { timeout: 60_000 }, () => {
  test("Genesis field 5; the root reads it from the package sent at creation; siblings and roster", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    await pair(w, w.P, 3, "edit");
    const r = await createResourceAsDevice({
      ...A,
      dataProfile: "org.example.v1",
      url: URL,
      name: "From A",
    });
    if (r.kind !== "created") throw new Error(r.kind);
    const g = r.chain.records[0]?.body;
    expect(g?.type === "GENESIS" && toHex(g.owner.principalId)).toBe(toHex(id(1)));
    expect(g?.type === "GENESIS" && g.deviceChain !== undefined).toBe(true);
    expect(r.rootKeys.sent.map((s) => s.recipient)).toEqual([toHex(id(1))]);
    expect(r.siblings.map((s) => s.status)).toEqual(["registered"]);
    expect(r.roster).toBe(true);
    // A goes offline; the root opens the Resource with its package.
    const deks = await fetchDeks(
      w.P.storage,
      w.P.secrets,
      await w.P.network.connect(w.P.installation.signer, URL),
      w.server.chain(r.resource),
      w.P.installation,
    );
    expect(deks.has("0")).toBe(true);
  });

  test("an Edit device cannot create a Resource for its root", async () => {
    const w = await world(0);
    const B = await pair(w, w.P, 3, "edit");
    expect((await createResourceAsDevice({ ...B, dataProfile: "x.v1", url: URL })).kind).toBe(
      "not-owner-acting",
    );
  });
});

describe("the revoked device (§8.6, W §41, F17)", { timeout: 60_000 }, () => {
  test("access refused versus revocation proven", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const B = await pair(w, w.P, 3, "edit");
    expect((await revocationStatus({ ...B, resource: w.I, url: URL })).kind).toBe("active");
    await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    for (const R of [w.I, X]) {
      const s = await revocationStatus({ ...B, resource: R as never, url: URL });
      if (s.kind !== "revocation-proven") throw new Error(s.kind);
      expect(s.reason).toBe(1n);
      const last = parseControlRecord(s.prefix.at(-1) as Uint8Array);
      expect(bytesEqual(last.signed.id, s.record)).toBe(true);
    }
    // A Principal that was never a reader proves nothing.
    const stranger = node(w.server, party(9));
    expect((await revocationStatus({ ...stranger, resource: X as never, url: URL })).kind).toBe(
      "access-refused",
    );
  });
});
