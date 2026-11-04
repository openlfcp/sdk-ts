import { actorSequence, bytesEqual } from "@openlfcp/core";
import type { LfcpStorage } from "@openlfcp/storage";
import { canonicalFrontierToCbor, receiveSnapshot, sealDataUnit } from "@openlfcp/wire";
import { encode } from "@openlfcp/wire/cbor";
import { describe, expect, test } from "vitest";
import { DataUnitApplier } from "../../src/apply.js";
import { heldDeks } from "../../src/identity/context.js";
import { OperationJournal } from "../../src/identity/journal.js";
import { rotateAfter } from "../../src/identity/rotation.js";
import { createSnapshot } from "../../src/snapshot.js";
import { URL } from "./support.js";
import { world } from "./world.js";

// The rotation frontier against what this installation already stored
// (IDENTITY-PROFILE-01 §8.3; W §19.1, §26.2, §29.3), through rotateAfter.
async function setup() {
  const w = await world(1);
  const R = w.resources[0] as never;
  const chain = w.server.chain(R);
  const dek = (await heldDeks(w.P.secrets, chain)).get("0") as never;
  const actor = w.P.installation.signer.descriptor.principalId;
  const seal = (n: number, prev: Uint8Array | null, text: string) =>
    sealDataUnit(
      {
        resourceId: R,
        dataEpoch: chain.state.epoch.epoch,
        actorSeq: actorSequence(BigInt(n)),
        prevDataUnitId: prev as never,
        controlHead: chain.state.head,
      },
      new TextEncoder().encode(text),
      dek,
      w.P.installation.signer,
    );
  const a = seal(1, null, "one");
  const b = seal(2, a.unitId, "two");
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  const codec = {
    dataProfile: chain.state.dataProfile,
    encode: (v: Uint8Array) => v,
    decode: (v: Uint8Array) => v,
  };
  const applier = new DataUnitApplier({
    storage: w.P.storage,
    dek: () => dek,
    handlers: [
      {
        dataProfile: chain.state.dataProfile,
        codecFor: () => codec,
        apply: (u: { unitId: Uint8Array }) => ({
          merged: [u.unitId],
          objects: [],
          diagnostics: [],
        }),
        exclude: () => ({ objects: [], pending: [] }),
      },
    ],
  } as never);
  /** A verified Snapshot covering 1..2, stored as the client stores one it loaded. */
  const storeSnapshot = async () => {
    const snapshot = await createSnapshot({
      view: chain,
      controlHead: chain.state.head,
      publisher: w.P.installation.signer,
      dek,
      sequences: (w.P.storage as unknown as LfcpStorage).snapshotSequences,
      frontier: [{ principalId: actor, contiguous: 2n }],
      profile: codec,
      value: new TextEncoder().encode("one,two"),
    } as never);
    const loaded = await receiveSnapshot(chain, snapshot.bytes, { dek: () => dek, profile: codec });
    if (loaded.kind !== "accepted") throw new Error(loaded.kind);
    const r = await w.P.storage.commit([
      {
        op: "put-snapshot",
        row: {
          snapshotId: loaded.snapshotId,
          resourceId: R,
          dataEpoch: loaded.epoch,
          publisher: loaded.publisher,
          snapshotSeq: loaded.seq,
          frontier: encode(canonicalFrontierToCbor(loaded.frontier)),
          bytes: snapshot.bytes,
        },
      } as never,
    ]);
    if (!r.ok) throw new Error(r.reason);
  };
  const rotate = async (id: string) => {
    await new OperationJournal(w.P.storage).begin({ id, kind: "rotate", createdAt: 1, intent: {} });
    const out = await rotateAfter({ ...w.P, channel, resource: R, operation: id, revokedAt: 0n });
    expect(out.status).toBe("rotated");
    const last = w.server.chain(R).records.at(-1)?.body;
    if (last?.type !== "KEY_EPOCH") throw new Error("no KEY_EPOCH");
    const mine = last.finalFrontier.find((h) => bytesEqual(h.principalId, actor));
    return [mine?.contiguous, mine?.extras];
  };
  return { w, R, seal, a, b, applier, storeSnapshot, rotate };
}

describe("the rotation frontier and the local accepted set (re-review 12c)", {
  timeout: 60_000,
}, () => {
  test("12c.1: stored equivocation evidence keeps both twins out when a coordinator shows one", async () => {
    const { w, R, seal, a, b, applier, rotate } = await setup();
    const c = seal(3, b.unitId, "three");
    const d = seal(3, b.unitId, "twin");
    const chain = w.server.chain(R);
    for (const u of [a, b, c]) expect((await applier.receive(chain, u.bytes)).kind).toBe("applied");
    expect((await applier.receive(chain, d.bytes)).kind).toBe("equivocation");
    for (const u of [a, b, c]) w.server.inject(R, u.bytes);
    expect(await rotate("probe-equivocation")).toEqual([2n, []]);
  });

  test("12c.2: a gap after a verified Snapshot keeps the next unit that names its last unit", async () => {
    const { w, R, seal, b, storeSnapshot, rotate } = await setup();
    await storeSnapshot();
    // 3 was reserved and abandoned; 4 names 2, the Snapshot's last covered unit.
    w.server.inject(R, seal(4, b.unitId, "four").bytes);
    expect(await rotate("probe-gap")).toEqual([2n, [[4n, 4n]]]);
  });

  test("12c.2: a unit naming a unit older than the Snapshot's last is not accepted", async () => {
    const { w, R, seal, a, applier, storeSnapshot, rotate } = await setup();
    expect((await applier.receive(w.server.chain(R), a.bytes)).kind).toBe("applied");
    await storeSnapshot();
    w.server.inject(R, seal(3, a.unitId, "wrong previous").bytes);
    expect(await rotate("probe-previous")).toEqual([2n, []]);
  });
});
