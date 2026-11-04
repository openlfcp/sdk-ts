import { type PrincipalId, toHex } from "@openlfcp/core";
import { DEVICE_KIND, parseControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { MASK_PRESETS } from "../../src/identity/devices.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party } from "./support.js";
import { type Node, pair, recertifyInI, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const KEY_EPOCH = 4n;
const _isKeyEpoch = (bytes: Uint8Array) =>
  parseControlRecord(bytes).payload.controlType === KEY_EPOCH;
const _epochOf = (server: MemoryCoordinator, R: Uint8Array) =>
  server.chain(R as never).state.epoch.epoch;

describe("revocation recovery (review follow-up, IDENTITY-PROFILE-01 §8.1, §9.1)", {
  timeout: 120_000,
}, () => {
  test("12.5: a resumed self-retirement still reaches the roster from its journal", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const B = await pair(w, w.P, 3, "edit");
    w.server.fault = (e) =>
      e.op === "control" && toHex(e.resource) === toHex(w.I) && e.signer === B.installation.signer
        ? "drop-answer"
        : undefined;
    const first = await revokeDevice({ ...B, device: id(3), reason: 0n });
    expect(first.kind).toBe("unavailable");
    w.server.fault = () => undefined;
    const again = await revokeDevice({
      ...B,
      device: id(3),
      reason: 0n,
      operation: (first as { operation: string }).operation,
    });
    if (again.kind !== "revoked") throw new Error(again.kind);
    expect(again.results.map((r) => r.revoke)).toEqual(["complete", "revoked"]);
    expect(w.server.chain(X as never).state.revoked.has(`${toHex(id(1))}:${toHex(id(3))}`)).toBe(
      true,
    );
  });
  test("12.6: a revoker whose chain in X passes through the target does not propose there", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const D = await pair(w, w.P, 2, "full");
    const A: Node = await pair(w, D, 4, "full");
    await recertifyInI(w, 4, DEVICE_KIND.PERSONAL, MASK_PRESETS.full.mask, []);
    const r = await revokeDevice({ ...A, device: id(2), reason: 1n });
    if (r.kind !== "revoked") throw new Error(r.kind);
    expect(r.results.map((x) => x.revoke)).toEqual(["revoked", "self-dependent"]);
    expect(w.server.chain(X as never).state.revoked.has(`${toHex(id(1))}:${toHex(id(2))}`)).toBe(
      false,
    );
  });
});
