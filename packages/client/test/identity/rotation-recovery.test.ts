import { bytesEqual, dataEpoch, type PrincipalId, toHex } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { parseControlRecord, parseDataUnit, sealDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks } from "../../src/identity/context.js";
import { revokeDevice } from "../../src/identity/revocation.js";
import { verifiedFrontier } from "../../src/identity/rotation.js";
import type { MemoryCoordinator } from "./memory-coordinator.js";
import { party, URL } from "./support.js";
import { pair, world } from "./world.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const KEY_EPOCH = 4n;
const isKeyEpoch = (bytes: Uint8Array) =>
  parseControlRecord(bytes).payload.controlType === KEY_EPOCH;
const epochOf = (server: MemoryCoordinator, R: Uint8Array) =>
  server.chain(R as never).state.epoch.epoch;

describe("rotation recovery (review follow-up, IDENTITY-PROFILE-01 §8.3, §9.1–§9.3)", {
  timeout: 120_000,
}, () => {
  test("12.1: a resumed own KEY_EPOCH adopts its DEK for its own epoch after another rotator's", async () => {
    const w = await world(1);
    const X = w.resources[0] as Uint8Array;
    const A = await pair(w, w.P, 2, "full");
    await pair(w, w.P, 3, "edit");
    await pair(w, w.P, 4, "read");
    const e0 = epochOf(w.server, X);
    w.server.fault = (e) =>
      e.op === "control" &&
      toHex(e.resource) === toHex(X) &&
      isKeyEpoch(e.bytes) &&
      e.signer === A.installation.signer
        ? "drop-answer"
        : undefined;
    const first = await revokeDevice({ ...A, device: id(3), reason: 1n });
    if (first.kind !== "revoked") throw new Error(first.kind);
    expect(first.results[1]?.rotation?.status).toBe("unreachable");
    w.server.fault = () => undefined;
    await revokeDevice({ ...w.P, device: id(4), reason: 1n });
    expect(epochOf(w.server, X)).toBe(e0 + 2n);
    const resumed = await revokeDevice({
      ...A,
      device: id(3),
      reason: 1n,
      operation: first.operation,
    });
    if (resumed.kind !== "revoked") throw new Error(resumed.kind);
    expect((await heldDeks(A.secrets, w.server.chain(X as never))).has(String(e0 + 1n))).toBe(true);
  });
  test("12.3: a KEY_EPOCH sent again on the same head covers units accepted meanwhile", async () => {
    const w = await world(0);
    await pair(w, w.P, 2, "full");
    let dropped = false;
    w.server.fault = (e) => {
      if (dropped || e.op !== "control" || toHex(e.resource) !== toHex(w.I) || !isKeyEpoch(e.bytes))
        return undefined;
      dropped = true;
      return "drop-request";
    };
    const first = await revokeDevice({ ...w.P, device: id(2), reason: 1n });
    if (first.kind !== "revoked") throw new Error(first.kind);
    w.server.fault = () => undefined;
    const before = Math.max(
      ...w.server
        .unitsOf(w.I)
        .filter((u) => bytesEqual(u.actor, id(1)))
        .map((u) => Number(u.actorSeq)),
    );
    await revokeDevice({ ...w.P, device: id(2), reason: 1n, operation: first.operation });
    const last = w.server.chain(w.I).records.at(-1);
    if (last?.body.type !== "KEY_EPOCH") throw new Error("no KEY_EPOCH");
    const mine = last.body.finalFrontier.find((h) => bytesEqual(h.principalId, id(1)));
    expect(Number(mine?.contiguous ?? 0n)).toBeGreaterThanOrEqual(before);
  });
  test("12.7: the frontier leaves out both units of an equivocation and what links to them", async () => {
    const w = await world(0);
    const units = [...(w.server.hosted.get(toHex(w.I))?.units.values() ?? [])];
    const unit2 = units.find((b) => parseDataUnit(b).payload.actorSeq === 2n) as Uint8Array;
    const chain = w.server.chain(w.I);
    const dek = (await heldDeks(w.P.secrets, chain)).get("0");
    const seal = (seq: bigint, prev: Uint8Array, text: string) =>
      sealDataUnit(
        {
          resourceId: w.I,
          dataEpoch: dataEpoch(0n),
          actorSeq: seq as never,
          prevDataUnitId: prev as never,
          controlHead: chain.state.head,
        },
        new TextEncoder().encode(text),
        dek as never,
        w.P.installation.signer,
      );
    const a = seal(3n, sha256(unit2), "a");
    const b = seal(3n, sha256(unit2), "b");
    const c = seal(4n, a.unitId, "c");
    for (const u of [a, b, c]) w.server.inject(w.I, u.bytes);
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    const frontier = await verifiedFrontier(
      channel,
      chain,
      { units: [], snapshot: [] },
      { deks: await heldDeks(w.P.secrets, chain) },
    );
    const mine = frontier.find((h) => bytesEqual(h.principalId, id(1)));
    expect([mine?.contiguous, mine?.extras]).toEqual([2n, []]);
  });

  async function rootUnits() {
    const w = await world(0);
    const units = [...(w.server.hosted.get(toHex(w.I))?.units.values() ?? [])];
    const at = (seq: bigint) =>
      units.find((b) => parseDataUnit(b).payload.actorSeq === seq) as Uint8Array;
    const chain = w.server.chain(w.I);
    const dek = (await heldDeks(w.P.secrets, chain)).get("0");
    const seal = (seq: bigint, prev: Uint8Array, text: string) =>
      sealDataUnit(
        {
          resourceId: w.I,
          dataEpoch: dataEpoch(0n),
          actorSeq: seq as never,
          prevDataUnitId: prev as never,
          controlHead: chain.state.head,
        },
        new TextEncoder().encode(text),
        dek as never,
        w.P.installation.signer,
      );
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    return { w, at, chain, seal, channel };
  }
  const contiguousOf = (
    frontier: readonly {
      principalId: Uint8Array;
      contiguous: bigint;
      extras: readonly unknown[];
    }[],
  ) => {
    const mine = frontier.find((h) => bytesEqual(h.principalId, id(1)));
    return [mine?.contiguous, mine?.extras];
  };

  test("12b.1: a stored unit and a fetched one at one sequence are both left out", async () => {
    const { w, at, chain, seal, channel } = await rootUnits();
    const stored = seal(3n, sha256(at(2n)), "stored");
    const fetched = seal(3n, sha256(at(2n)), "fetched");
    w.server.inject(w.I, fetched.bytes);
    const frontier = await verifiedFrontier(
      channel,
      chain,
      { units: [stored.bytes], snapshot: [] },
      { deks: await heldDeks(w.P.secrets, chain) },
    );
    expect(contiguousOf(frontier)).toEqual([2n, []]);
  });

  test("12b.1: a unit naming an older unit than the actor's latest is not accepted", async () => {
    const { w, at, chain, seal, channel } = await rootUnits();
    w.server.inject(w.I, seal(3n, sha256(at(1n)), "skips 2").bytes);
    const deks = await heldDeks(w.P.secrets, chain);
    const frontier = await verifiedFrontier(channel, chain, { units: [], snapshot: [] }, { deks });
    expect(contiguousOf(frontier)).toEqual([2n, []]);
  });
});
