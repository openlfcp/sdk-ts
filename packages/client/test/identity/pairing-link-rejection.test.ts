import { type ResourceId, toHex } from "@openlfcp/core";
import { InvitationSecret } from "@openlfcp/crypto";
import { assemblePairingUri, DEVICE_KIND, invitationPrincipal } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { leafPayload, registerDevice, signChain } from "../../src/identity/devices.js";
import { OperationJournal, pairingSecretRef } from "../../src/identity/journal.js";
import {
  approvePairing,
  createPairingSession,
  pairingRequests,
} from "../../src/identity/pairing.js";
import { requestPairing } from "../../src/identity/pairing-request.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import { party, URL } from "./support.js";
import { hostResource, node, pair, world } from "./world.js";

// IDENTITY-PROFILE-01 §5.2 through the real requestPairing (review
// LFCP-04-415f finding 5; F08.link_rejected): a link that fails one check
// is rejected with a client-local outcome, after which nothing more is sent
// as J or as the installation (no upload), no request is written in I, no
// operation is journaled and the link's secret is not kept.

type World = Awaited<ReturnType<typeof world>>;

/** A pairing link for a fresh secret, naming `resource` (default I). */
function link(w: World, resource: ResourceId = w.I) {
  const secret = InvitationSecret.generate();
  const J = invitationPrincipal(secret);
  return {
    J,
    uri: assemblePairingUri({
      identityResourceId: resource,
      endpoints: [URL],
      pairingDevice: J.principalId,
      secret,
    }),
  };
}

/** Binds `J` in `resource` with the root's direct certificate. */
async function bind(
  w: World,
  resource: ResourceId,
  J: ReturnType<typeof invitationPrincipal>,
  kind: 0 | 2,
  scope: readonly ResourceId[],
) {
  const leaf = leafPayload(party(1).signer.descriptor.principalId, J, kind, [1n, 2n], scope);
  const chain = signChain(w.server.chain(resource).state, w.P.installation.signer, leaf);
  const r = await registerDevice({ ...w.P, chain, targets: [{ resource, url: URL }] });
  expect(r.results[0]?.status).toBe("registered");
}

/** requestPairing on `uri` by a fresh installation: rejected, and nothing follows. */
async function expectRejected(
  w: World,
  uri: Parameters<typeof requestPairing>[0]["link"],
  kind: "not-a-session" | "invalid-link",
  J?: ReturnType<typeof invitationPrincipal>,
) {
  const B = node(w.server, party(30));
  const uploads = w.server.uploads.length;
  const units = w.server.unitsBytes(w.I).length;
  const r = await requestPairing({ ...B, link: uri, label: "b", kind: 0 });
  expect(r.kind).toBe(kind);
  // reported: the outcome names the failed check.
  expect(r.kind === kind && "reason" in r && r.reason.length > 0).toBe(true);
  // sent_as_pairing_device_after_rejection: nothing; request_written: false.
  expect(w.server.uploads.length).toBe(uploads);
  expect(w.server.unitsBytes(w.I).length).toBe(units);
  expect(await new OperationJournal(B.storage).list()).toEqual([]);
  if (J !== undefined) expect(await B.secrets.get(pairingSecretRef(J.principalId))).toBeUndefined();
  return r;
}

describe("a rejected pairing link writes and sends nothing (IDENTITY-PROFILE-01 §5.2, F08.link_rejected)", {
  timeout: 120_000,
}, () => {
  test("control: every check passes, the request is written as J", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    const B = node(w.server, party(30));
    const units = w.server.unitsBytes(w.I).length;
    const r = await requestPairing({ ...B, link: s.link, label: "b", kind: 0 });
    expect(r.kind).toBe("requested");
    expect(w.server.unitsBytes(w.I).length).toBe(units + 1);
  });

  test("I's Genesis profile is not org.openlfcp.identity.v1", async () => {
    const w = await world(0);
    const X = (await hostResource(w.server, w.P)).resource;
    const l = link(w, X);
    // J is a pairing device of the owner and a reader of X: only the profile check fails.
    await bind(w, X, l.J, DEVICE_KIND.PAIRING, [X]);
    const r = await expectRejected(w, l.uri, "not-a-session", l.J);
    expect(r.kind === "not-a-session" && r.reason).toMatch(/not an Identity Resource/);
  });

  test("device names a kind-0 device", async () => {
    const w = await world(0);
    const l = link(w);
    await bind(w, w.I, l.J, DEVICE_KIND.PERSONAL, []);
    const r = await expectRejected(w, l.uri, "not-a-session", l.J);
    expect(r.kind === "not-a-session" && r.reason).toMatch(
      /not a registered, active pairing device/,
    );
  });

  test("device names a pairing device whose session is consumed", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    // The session is approved for DEV_3 (DEVICE_REVOKE {R, J, 3}); the link is used again.
    const B = node(w.server, party(3));
    expect((await requestPairing({ ...B, link: s.link, label: "b", kind: 0 })).kind).toBe(
      "requested",
    );
    const [review] = await pairingRequests({ ...w.P, session: s.session });
    if (review === undefined) throw new Error("no request");
    expect((await approvePairing({ ...w.P, review, preset: "read" })).kind).toBe("approved");
    // J still reads I's revoked-reader prefix (W §41); the chain shows it revoked.
    const r = await expectRejected(w, s.link, "not-a-session");
    expect(r.kind === "not-a-session" && r.reason).toMatch(
      /not a registered, active pairing device/,
    );
  });

  test("device names a cancelled pairing device", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    await revokeDevice({ ...w.P, device: s.pairingDevice, reason: 0n });
    const r = await expectRejected(w, s.link, "not-a-session");
    expect(r.kind === "not-a-session" && r.reason).toMatch(
      /not a registered, active pairing device/,
    );
  });

  test("device names a suspended pairing device (its issuer is revoked)", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const s = await createPairingSession(A);
    if (s.kind !== "created") throw new Error(s.kind);
    await revokeDevice({ ...w.P, device: party(2).signer.descriptor.principalId, reason: 1n });
    // A suspended device is no reader: the coordinator refuses the session as J (W §41).
    const r = await expectRejected(w, s.link, "not-a-session");
    expect(r.kind === "not-a-session" && r.reason).toMatch(/refused/);
  });

  test("device names a pairing device not registered in I: the coordinator refuses the session as J", async () => {
    const w = await world(0);
    const l = link(w);
    const r = await expectRejected(w, l.uri, "not-a-session", l.J);
    expect(r.kind === "not-a-session" && r.reason).toMatch(/refused/);
  });

  test("a valid link whose session as J the coordinator refuses (an older prefix of I)", async () => {
    const w = await world(0);
    const s = await createPairingSession(w.P);
    if (s.kind !== "created") throw new Error(s.kind);
    // The coordinator serves the valid prefix from before J was registered.
    w.server.hosted.get(toHex(w.I))?.records.splice(1);
    const r = await expectRejected(w, s.link, "not-a-session");
    expect(r.kind === "not-a-session" && r.reason).toMatch(/refused/);
  });

  test("the secret's Principal is not device", async () => {
    const w = await world(0);
    const a = link(w);
    const b = link(w);
    // a's secret with b's device parameter.
    const device = (u: string) => /[?&]device=([^&#]+)/.exec(u)?.[1] as string;
    const mixed = a.uri.replace(`device=${device(a.uri)}`, `device=${device(b.uri)}`);
    expect(mixed).not.toBe(a.uri);
    const r = await expectRejected(w, mixed, "invalid-link", a.J);
    expect(r.kind === "invalid-link" && r.reason).toMatch(/not the device's/);
  });
});
