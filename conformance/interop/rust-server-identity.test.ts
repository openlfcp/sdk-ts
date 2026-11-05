// LFCP-04-412: the identity flows of @openlfcp/client end to end against the
// Rust reference server at server.lock (identity-01, mvp-0.4-baseline.2,
// hosting by the Genesis owner, I12), over a real WebSocket. The root P
// creates its Identity Resource I over a Resource X it hosts; pairs A
// (Full) and B (Edit) through links, with the fingerprint both sides show,
// approval and the registration in X; B, which holds no key/distribute,
// seals X's DEK to its root (the same-root Key Package of W §25.2) and is
// refused for a foreign recipient; P revokes A, I and X rotate, B (issued
// by A) is suspended by the cascade and reads nothing, and A reads only
// the Control prefix through its revocation (W §41) and proves it.
//
// Skipped (saying why) without a server checkout or cargo, unless
// LFCP_REQUIRE_LIVE=1; LFCP_SERVER_BIN runs a prebuilt server instead.

import {
  approvePairing,
  completePairing,
  createIdentityResource,
  createPairingSession,
  fetchDeks,
  IdentityRefused,
  pairingRequests,
  requestPairing,
  revocationStatus,
  revokeDevice,
  syncChain,
} from "@openlfcp/client";
import { bytesEqual, dataEpoch, type ResourceId, toHex } from "@openlfcp/core";
import {
  activeDevice,
  deviceFingerprint,
  revocationOf,
  sealKeyPackage,
  validateControlChain,
} from "@openlfcp/wire";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { party } from "../../packages/client/test/identity/support.js";
import { chainOf, hostResource, installation, type Node } from "./identity-live.js";
import { type RunningRustServer, startRustServer } from "./rust-server.mjs";

let server: RunningRustServer | undefined;
let skip: string | undefined;

beforeAll(async () => {
  const started = await startRustServer();
  if ("skip" in started) skip = started.skip;
  else server = started;
}, 600_000);

afterAll(async () => {
  await server?.stop();
});

/** Pairs `n` through `approver` with `preset`; returns the new installation and what both sides showed. */
async function pair(approver: Node, n: number, preset: "full" | "edit") {
  const session = await createPairingSession(approver);
  if (session.kind !== "created") throw new Error(`session: ${JSON.stringify(session)}`);
  const B = installation(n);
  const request = await requestPairing({
    ...B,
    link: session.link,
    label: `installation ${n}`,
    kind: 0,
    platform: "desktop",
  });
  if (request.kind !== "requested") throw new Error(`request: ${JSON.stringify(request)}`);
  const [review] = await pairingRequests({ ...approver, session: session.session });
  if (review === undefined) throw new Error("the approver sees no request");
  const approved = await approvePairing({ ...approver, review, preset });
  if (approved.kind !== "approved") throw new Error(`approval: ${JSON.stringify(approved)}`);
  const done = await completePairing({ ...B, operation: request.operation });
  return { B, request, review, done };
}

describe("identity flows against the Rust reference server", { timeout: 300_000 }, () => {
  const P = installation(41);
  let url = "";
  let X: Awaited<ReturnType<typeof hostResource>>;
  let I: ResourceId;
  let A: Node;
  let B: Node;

  it("hosts X and creates the Identity Resource on a server with identity-01", async () => {
    if (server === undefined) return void console.warn(`skipped: ${skip}`);
    url = server.url;
    const channel = await P.network.connect(P.installation.signer, url);
    expect(channel.extensions).toContain("identity-01");
    channel.close();
    X = await hostResource(P, url);
    const created = await createIdentityResource({
      ...P,
      url,
      label: "laptop",
      roster: [X],
    });
    if (created.kind !== "created") throw new Error(JSON.stringify(created));
    I = created.identity;
    const chain = await chainOf(P, url, I);
    expect(chain.state.dataProfile).toBe("org.openlfcp.identity.v1");
  });

  it("pairs A (Full) through a link: the same fingerprint on both sides, approved, registered in I and X", async () => {
    if (server === undefined) return;
    const r = await pair(P, 42, "full");
    A = r.B;
    const fp = deviceFingerprint(A.installation.signer.descriptor.principalId);
    expect(r.request.kind === "requested" && r.request.fingerprint).toBe(fp);
    expect(r.review.fingerprint).toBe(fp);
    if (r.done.kind !== "approved" || r.done.certificate === null)
      throw new Error(`complete: ${JSON.stringify(r.done)}`);
    expect(r.done.candidates.map((c) => [toHex(c.resource), c.status]).sort()).toEqual(
      [
        [toHex(I), "ready"],
        [toHex(X.resource), "ready"],
      ].sort(),
    );
    const x = await chainOf(A, url, X.resource);
    expect(activeDevice(x.state, A.installation.signer.descriptor.principalId)?.root).toEqual(
      P.installation.signer.descriptor.principalId,
    );
  });

  it("pairs B (Edit) through A, a managing device", async () => {
    if (server === undefined) return;
    const r = await pair(A, 43, "edit");
    B = r.B;
    if (r.done.kind !== "approved" || r.done.certificate === null)
      throw new Error(`complete: ${JSON.stringify(r.done)}`);
    expect(r.done.certificate.issuers.map(toHex)).toEqual([
      toHex(A.installation.signer.descriptor.principalId),
    ]);
    expect(r.done.candidates.every((c) => c.status === "ready")).toBe(true);
  });

  it("the same-root Key Package: B (no key/distribute) seals X's DEK to its root, not to a stranger", async () => {
    if (server === undefined) return;
    const channel = await B.network.connect(B.installation.signer, url);
    try {
      const x = await syncChain(B.storage, channel, X.resource);
      const deks = await fetchDeks(B.storage, B.secrets, channel, x, B.installation);
      const dek = deks.get("0");
      if (dek === undefined) throw new Error("B holds no DEK of X");
      const to = (recipient: typeof P.installation.signer.descriptor) =>
        sealKeyPackage({
          resourceId: X.resource,
          epoch: dataEpoch(0n),
          controlHead: x.state.head,
          recipient,
          dek,
          signer: B.installation.signer,
        });
      const root = await channel.putKeyPackage(
        X.resource,
        (await to(P.installation.signer.descriptor)).bytes,
      );
      expect(root.kind).toBe("ack");
      const stranger = await channel.putKeyPackage(
        X.resource,
        (await to(party(49).signer.descriptor)).bytes,
      );
      expect(stranger).toMatchObject({ kind: "nack", code: "AUTHORIZATION_FAILED" });
    } finally {
      channel.close();
    }
  });

  it("revokes A: I and X record it and rotate; B, issued by A, is suspended and reads nothing", async () => {
    if (server === undefined) return;
    const a = A.installation.signer.descriptor.principalId;
    // I rotated already as each pairing session closed (§5.3 step 9); X never did.
    const before = new Map<string, bigint>();
    for (const resource of [I, X.resource])
      before.set(toHex(resource), (await chainOf(P, url, resource)).state.epoch.epoch);
    expect(before.get(toHex(X.resource))).toBe(0n);
    const r = await revokeDevice({ ...P, device: a, reason: 1n });
    if (r.kind !== "revoked") throw new Error(JSON.stringify(r));
    for (const resource of [I, X.resource]) {
      const chain = await chainOf(P, url, resource);
      expect(
        revocationOf(chain.state, P.installation.signer.descriptor.principalId, a),
      ).toBeDefined();
      // The revocation exposed a reader: the owner rotated (decision I6).
      expect(chain.state.epoch.epoch).toBe((before.get(toHex(resource)) ?? 0n) + 1n);
    }
    // B, issued by A, is suspended by the cascade (W §17.5) and was never revoked itself:
    // not a reader after the revocation, so it gets nothing, not even the Control prefix
    // (W §41; LFCP-IDENTITY-TEST-VECTORS-01 OPEN_as_dev_b.I9), and no key of the new epoch.
    const x = await chainOf(P, url, X.resource);
    const b = B.installation.signer.descriptor.principalId;
    expect(x.state.devices.get(toHex(b))?.registered).toBe(true);
    expect(activeDevice(x.state, b)).toBeUndefined();
    await expect(chainOf(B, url, X.resource)).rejects.toBeInstanceOf(IdentityRefused);
  });

  it("the revoked A reads the Control prefix through its revocation only, and proves it", async () => {
    if (server === undefined) return;
    const a = A.installation.signer.descriptor.principalId;
    const channel = await A.network.connect(A.installation.signer, url);
    try {
      const records = await channel.control(X.resource, 0n);
      const prefix = validateControlChain([...records]);
      if (prefix.kind !== "linear") throw new Error(prefix.kind);
      const last = prefix.records.at(-1);
      // The prefix ends at the record that revoked A: the rotation after it is not served.
      expect(last?.body.type).toBe("DEVICE_REVOKE");
      expect(last?.body.type === "DEVICE_REVOKE" && bytesEqual(last.body.device, a)).toBe(true);
      await expect(
        channel.dataUnits(X.resource, [{ actor: a, start: 1n, end: 1n }]),
      ).rejects.toBeInstanceOf(IdentityRefused);
      await expect(channel.keyPackages(X.resource, a, [dataEpoch(1n)])).rejects.toBeInstanceOf(
        IdentityRefused,
      );
    } finally {
      channel.close();
    }
    const status = await revocationStatus({ ...A, resource: X.resource, url });
    expect(status.kind).toBe("revocation-proven");
  });
});

declare const console: { warn(...a: unknown[]): void };
