import { type PrincipalId, type ResourceId, toHex } from "@openlfcp/core";
import { decodeControlRecord, parseKeyPackage, revocationOf } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party } from "./support.js";
import { pair, world } from "./world.js";

// IDENTITY-PROFILE-01 §7.1 step 1 (review LFCP-04-415f, finding 1): while a
// pair of I's `revoked` is unpropagated in X, nothing is sealed to its device
// in X, by step 3 or by a rotation (rotateIfExposed, rotateAfter, a resumed
// rotation): every KEY_PACKAGE_PUT of the operation is checked.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const hex = (b: Uint8Array) => toHex(b);

/** The recipients (hex) of the Key Packages uploaded to X from upload index `from` on. */
const sealedTo = (server: MemoryCoordinator, X: ResourceId, from: number) =>
  server.uploads
    .slice(from)
    .filter((e) => e.op === "key-package" && hex(e.resource) === hex(X))
    .map((e) => hex(parseKeyPackage(e.bytes).payload.recipient));

/** X refuses the revocation of `device` (as at the limit of W §17.5 rule 5). */
const refuseRevocationOf = (server: MemoryCoordinator, X: ResourceId, device: PrincipalId) => {
  server.fault = (e) => {
    if (e.op !== "control" || hex(e.resource) !== hex(X)) return undefined;
    const b = decodeControlRecord(e.bytes).body;
    return b.type === "DEVICE_REVOKE" && hex(b.device) === hex(device)
      ? { nack: "AUTHORIZATION_FAILED" }
      : undefined;
  };
};

/**
 * DEV_3, DEV_4 and DEV_6 paired; DEV_3 and DEV_4 revoked in I while X was
 * unreachable: X counts both as active. DEV_6 stays a reader of X.
 */
async function twoRevokedInIOnly() {
  const w = await world(1);
  const X = w.resources[0] as ResourceId;
  await pair(w, w.P, 3, "read");
  await pair(w, w.P, 4, "read");
  await pair(w, w.P, 6, "read");
  w.server.down.add(hex(X));
  await revokeDevice({ ...w.P, device: id(3), reason: 1n });
  await revokeDevice({ ...w.P, device: id(4), reason: 1n });
  w.server.down.clear();
  return { w, X };
}

describe("a rotation seals nothing to an unpropagated device (IDENTITY-PROFILE-01 §7.1 step 1)", {
  timeout: 120_000,
}, () => {
  test("reconciliation: a refused revocation and another exposing one, rotated by the same run", async () => {
    const { w, X } = await twoRevokedInIOnly();
    refuseRevocationOf(w.server, X, id(3));
    const before = w.server.uploads.length;
    const epochBefore = w.server.chain(X).state.epoch.epoch;
    const r = await reconcileDevices(w.P);
    const x = r.targets.find((t) => hex(t.resource) === hex(X));
    expect(x?.unpropagated?.map(hex)).toEqual([hex(id(3))]);
    expect(x?.rotation?.status).toBe("rotated");
    expect(w.server.chain(X).state.epoch.epoch).toBeGreaterThan(epochBefore);
    expect(x?.keys?.sent.map((p) => p.recipient)).not.toContain(hex(id(3)));
    expect(x?.rotation?.keys?.sent.map((p) => p.recipient)).not.toContain(hex(id(3)));
    // Every KEY_PACKAGE_PUT of the operation, and every package of the new epoch on X.
    const sealed = sealedTo(w.server, X, before);
    expect(sealed.length).toBeGreaterThan(0);
    expect(sealed).not.toContain(hex(id(3)));
    const epoch = w.server.chain(X).state.epoch.epoch;
    expect(
      w.server
        .packagesOf(X)
        .filter((p) => p.dataEpoch === epoch)
        .map((p) => hex(p.recipient)),
    ).not.toContain(hex(id(3)));
    // The other reader receives the new epoch: the rotation is not withheld from readers.
    expect(sealed).toContain(hex(id(6)));
  });

  test("a rotation an earlier revocation committed is resumed without sealing to the unpropagated device", async () => {
    const { w, X } = await twoRevokedInIOnly();
    // DEV_5's revocation in X is exposing; the answer to its KEY_EPOCH is lost.
    await pair(w, w.P, 5, "read");
    w.server.fault = (e) =>
      e.op === "control" &&
      hex(e.resource) === hex(X) &&
      decodeControlRecord(e.bytes).body.type === "KEY_EPOCH"
        ? "drop-answer"
        : undefined;
    // DEV_3 and DEV_4 are still only revoked in I: X is reached here for DEV_5 only.
    const lost = await revokeDevice({ ...w.P, device: id(5), reason: 1n });
    expect(lost.kind).toBe("revoked");
    const xr =
      lost.kind === "revoked" ? lost.results.find((t) => hex(t.resource) === hex(X)) : undefined;
    expect(xr?.rotation?.status).toBe("unreachable");
    expect(revocationOf(w.server.chain(X).state, id(1), id(3))).toBeUndefined();
    refuseRevocationOf(w.server, X, id(3));
    const before = w.server.uploads.length;
    const r = await reconcileDevices({ ...w.P, rotate: false });
    expect(r.targets.find((t) => hex(t.resource) === hex(X))?.unpropagated?.map(hex)).toEqual([
      hex(id(3)),
    ]);
    const sealed = sealedTo(w.server, X, before);
    // The resumed rotation delivered the new epoch, to DEV_6 and not to DEV_3.
    expect(sealed).toContain(hex(id(6)));
    expect(sealed).not.toContain(hex(id(3)));
  });

  test("revokeDevice: the rotation after an exposing revocation skips a device I revoked earlier", async () => {
    const w = await world(1);
    const X = w.resources[0] as ResourceId;
    await pair(w, w.P, 3, "read");
    await pair(w, w.P, 4, "read");
    await pair(w, w.P, 6, "read");
    w.server.down.add(hex(X));
    await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    w.server.down.clear();
    const before = w.server.uploads.length;
    const r = await revokeDevice({ ...w.P, device: id(4), reason: 1n });
    const x = r.kind === "revoked" ? r.results.find((t) => hex(t.resource) === hex(X)) : undefined;
    expect(x?.revoke).toBe("revoked");
    expect(x?.rotation?.status).toBe("rotated");
    const sealed = sealedTo(w.server, X, before);
    expect(sealed).toContain(hex(id(6)));
    expect(sealed).not.toContain(hex(id(3)));
  });
});
