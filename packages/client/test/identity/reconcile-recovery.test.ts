import { type PrincipalId, toHex } from "@openlfcp/core";
import { DEVICE_KIND, parseControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks } from "../../src/identity/context.js";
import { MASK_PRESETS } from "../../src/identity/devices.js";
import { reconcileDevices } from "../../src/identity/reconcile.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party } from "./support.js";
import { pair, recertifyInI, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const KEY_EPOCH = 4n;
const isKeyEpoch = (bytes: Uint8Array) =>
  parseControlRecord(bytes).payload.controlType === KEY_EPOCH;
const _epochOf = (server: MemoryCoordinator, R: Uint8Array) =>
  server.chain(R as never).state.epoch.epoch;

describe("reconciliation recovery (review follow-up, IDENTITY-PROFILE-01 §7.1, §9.1)", {
  timeout: 120_000,
}, () => {
  test("12.2: reconciliation finishes a rotation an earlier run committed without its ACK", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const B = await pair(w, w.P, 3, "edit");
    await revokeDevice({ ...B, device: id(3), reason: 0n });
    w.server.fault = (e) =>
      e.op === "control" && toHex(e.resource) === toHex(X) && isKeyEpoch(e.bytes)
        ? "drop-answer"
        : undefined;
    await reconcileDevices(w.P);
    w.server.fault = () => undefined;
    await reconcileDevices(w.P);
    const chain = w.server.chain(X as never);
    expect((await heldDeks(w.P.secrets, chain)).has(String(chain.state.epoch.epoch))).toBe(true);
  });
  test("12.4: a suspended service device is re-certified in X from I's chain", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const A = await pair(w, w.P, 2, "full");
    await pair(w, A, 5, "service", { kind: 1, scope: [X as never] });
    await recertifyInI(w, 5, DEVICE_KIND.SERVICE, MASK_PRESETS.service.mask, [X]);
    await revokeDevice({ ...w.P, device: id(2), reason: 1n });
    const suspended = w.server.chain(X as never).state.devices.get(toHex(id(5)));
    expect(suspended?.issuers.map(toHex)).toEqual([toHex(id(2))]);
    await reconcileDevices(w.P);
    const after = w.server.chain(X as never).state.devices.get(toHex(id(5)));
    expect(after?.issuers).toEqual([]);
  });
});
