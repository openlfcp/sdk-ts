import { actorSequence, bytesEqual, type DataUnitId } from "@openlfcp/core";
import { generateResourceDEK } from "@openlfcp/crypto";
import { sealDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks } from "../../src/identity/context.js";
import { OperationJournal } from "../../src/identity/journal.js";
import { rotateAfter } from "../../src/identity/rotation.js";
import { URL } from "./support.js";
import { world } from "./world.js";

// The rotation frontier counts only units recipients accept as data
// (W §26.3 rules 6 and 7, §19; IDENTITY-PROFILE-01 §8.3). Reproduces 414:
// junk units signed with A's key and accepted by the server, then honest
// units of A at 11 and 12 that name A's last good unit.
async function setup() {
  const w = await world(1);
  const R = w.resources[0] as never;
  const chain = w.server.chain(R);
  const dek = (await heldDeks(w.P.secrets, chain)).get("0") as never;
  const actor = w.P.installation.signer.descriptor.principalId;
  const seal = (n: number, prev: DataUnitId | null, text: string, key = dek) =>
    sealDataUnit(
      {
        resourceId: R,
        dataEpoch: chain.state.epoch.epoch,
        actorSeq: actorSequence(BigInt(n)),
        prevDataUnitId: prev,
        controlHead: chain.state.head,
      },
      new TextEncoder().encode(text),
      key,
      w.P.installation.signer,
    );
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  /** Units 1..8 of A, honest. */
  let prev: DataUnitId | null = null;
  for (let n = 1; n <= 8; n++) {
    const u = seal(n, prev, `honest ${n}`);
    w.server.inject(R, u.bytes);
    prev = u.unitId;
  }
  const rotate = async (id: string, extra: object = {}) => {
    await new OperationJournal(w.P.storage).begin({ id, kind: "rotate", createdAt: 1, intent: {} });
    const out = await rotateAfter({
      ...w.P,
      ...extra,
      channel,
      resource: R,
      operation: id,
      revokedAt: 0n,
    });
    expect(out.status).toBe("rotated");
    const last = w.server.chain(R).records.at(-1)?.body;
    if (last?.type !== "KEY_EPOCH") throw new Error("no KEY_EPOCH");
    const mine = last.finalFrontier.find((h) => bytesEqual(h.principalId, actor));
    return [mine?.contiguous, mine?.extras];
  };
  return { w, R, seal, last8: prev as DataUnitId, rotate };
}

describe("the rotation frontier counts only data recipients accept", { timeout: 60_000 }, () => {
  test("units that fail AEAD stay out, and the honest units after them stay in (414)", async () => {
    const { w, R, seal, last8, rotate } = await setup();
    // Two junk units signed with A's key (a key that is not the epoch's DEK): the
    // server accepts them, no recipient can decrypt them.
    const junk = generateResourceDEK();
    const j9 = seal(9, last8, "junk 9", junk as never);
    const j10 = seal(10, j9.unitId, "junk 10", junk as never);
    // A never accepted 9 and 10: its next units name 8 (W §26.2).
    const h11 = seal(11, last8, "honest 11");
    const h12 = seal(12, h11.unitId, "honest 12");
    for (const u of [j9, j10, h11, h12]) w.server.inject(R, u.bytes);
    expect(await rotate("probe-aead")).toEqual([8n, [[11n, 12n]]]);
  });

  test("units the Data Profile rejects stay out when the profile is known", async () => {
    const { w, R, seal, last8, rotate } = await setup();
    const bad = seal(9, last8, "REJECT me");
    const h10 = seal(10, last8, "honest 10");
    for (const u of [bad, h10]) w.server.inject(R, u.bytes);
    const profile = {
      dataProfile: w.server.chain(R).state.dataProfile,
      encode: (v: Uint8Array) => v,
      decode: (v: Uint8Array) => {
        if (new TextDecoder().decode(v).startsWith("REJECT")) throw new Error("not a value");
        return v;
      },
    };
    expect(await rotate("probe-profile", { dataProfiles: [profile] })).toEqual([8n, [[10n, 10n]]]);
  });
});
