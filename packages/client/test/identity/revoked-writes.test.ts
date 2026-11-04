import { type PrincipalId, toHex } from "@openlfcp/core";
import { parseDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks } from "../../src/identity/context.js";
import { revocationStatus } from "../../src/identity/proof.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import { createQueuedDataUnit, loadControlChain, writeBarrier } from "../../src/storage.js";
import { party, URL } from "./support.js";
import { type Node, pair, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const _rosterPut =
  (w: Awaited<ReturnType<typeof world>>, A: Node) =>
  (e: { op: string; resource: Uint8Array; bytes: Uint8Array; signer: unknown }) =>
    e.op === "data-unit" &&
    toHex(e.resource) === toHex(w.I) &&
    e.signer === A.installation.signer &&
    toHex(parseDataUnit(e.bytes).payload.actor) === toHex(id(2));

describe("the revoked device writes nothing (review follow-up, IDENTITY-PROFILE-01 §8.6)", {
  timeout: 120_000,
}, () => {
  test("13.2: a proven revocation keeps the device from writing, even on its old chain", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const B = await pair(w, w.P, 3, "edit");
    await revokeDevice({ ...w.P, device: id(3), reason: 1n });
    expect((await revocationStatus({ ...B, resource: X as never, url: URL })).kind).toBe(
      "revocation-proven",
    );
    expect((await writeBarrier(B.storage, X as never))?.state).toBe("revocation-proven");
    const view = await loadControlChain(B.storage, X as never);
    if (view?.kind !== "linear") throw new Error("no chain");
    const dek = (await heldDeks(B.secrets, view)).get(String(view.state.epoch.epoch));
    const codec = {
      dataProfile: view.state.dataProfile,
      encode: (v: Uint8Array) => v,
      decode: (v: Uint8Array) => v,
    };
    await expect(
      createQueuedDataUnit(B.storage as never, {
        view,
        controlHead: view.state.head,
        actor: B.installation.signer,
        dek: dek as never,
        profile: codec,
        value: new Uint8Array([1]),
      }),
    ).rejects.toMatchObject({ code: "AUTHORIZATION_FAILED" });
  });
});
