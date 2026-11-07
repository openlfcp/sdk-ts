// The rotation frontier judges each unit as its recipients do, with the
// unit's own Resource and signer (LFCP-WIRE-01 §19, §26.3 rules 6 and 7;
// IDENTITY-PROFILE-01 §8.3), through FlowOptions.profiles (0.3.2). Review
// obsidian#109b: a unit signed by A that carries another actor's change
// (CHANGE_ACTOR_MISMATCH at every receiver) must not count, so that A's
// honest next unit stays within the frontier; and the Identity Resource's
// own rotation judges its units with the Identity Profile.

import {
  createIdentityResource,
  heldDeks,
  OperationJournal,
  rotateAfter,
  verifiedFrontier,
} from "@openlfcp/client";
import { actorSequence, type DataUnitId, type PrincipalId, toHex } from "@openlfcp/core";
import { frameChange } from "@openlfcp/shared-objects";
import { identityUnitProfile } from "@openlfcp/shared-objects/identity";
import {
  SECTIONS_PROFILE_ID,
  SectionReplica,
  sectionsCodecFor,
  sectionsUnitProfile,
} from "@openlfcp/shared-objects/sections";
import {
  type DataProfileCodec,
  hasSequence,
  InMemorySeenUnits,
  parseDataUnit,
  receiveDataUnit,
  sealDataUnit,
} from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { party, URL } from "../../packages/client/test/identity/support.js";
import { hostResource, node, world } from "../../packages/client/test/identity/world.js";
import { replicaPort } from "./replica-port.js";

type World = Awaited<ReturnType<typeof world>>;

/** Rotates `R` as P with `extra` flow options; P's entry in the KEY_EPOCH's final frontier. */
async function rotate(w: World, R: Uint8Array, extra: object = {}) {
  const id = `rotate.${toHex(R).slice(0, 8)}.${Math.random().toString(16).slice(2)}`;
  await new OperationJournal(w.P.storage).begin({ id, kind: "rotate", createdAt: 1, intent: {} });
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  const out = await rotateAfter({
    ...w.P,
    ...extra,
    channel,
    resource: R as never,
    operation: id,
    revokedAt: 0n,
  });
  expect(out.status).toBe("rotated");
  const last = w.server.chain(R as never).records.at(-1)?.body;
  if (last?.type !== "KEY_EPOCH") throw new Error("no KEY_EPOCH");
  return last.finalFrontier;
}

/** A shared section of P, with A/1 (signed by P, another actor's change) and A/2 (P's own). */
async function wrongActorSection(w: World) {
  const X = await hostResource(w.server, w.P, SECTIONS_PROFILE_ID);
  const chain = w.server.chain(X.resource);
  const me = w.P.installation.signer.descriptor.principalId;
  const change = (principal: PrincipalId) => {
    const made = SectionReplica.empty({ resource: X.resource, principal }).commit([
      {
        intent: "section.create",
        sectionId: "0192e4a0-0000-7000-8000-000000000001",
        title: "Valid data",
        createdBy: principal,
      },
    ]);
    if (made === null) throw new Error("no change");
    return frameChange(made.change);
  };
  const seal = (seq: bigint, body: Uint8Array) =>
    sealDataUnit(
      {
        resourceId: X.resource,
        dataEpoch: chain.state.epoch.epoch,
        actorSeq: actorSequence(seq),
        prevDataUnitId: null,
        controlHead: chain.state.head,
      },
      body,
      X.dek,
      w.P.installation.signer,
    );
  // A/2 names no unit: A/1 is no accepted unit at any receiver (W §26.2).
  const bad = seal(1n, change(party(2).signer.descriptor.principalId));
  const good = seal(2n, change(me));
  const receive = (bytes: Uint8Array) =>
    receiveDataUnit(w.server.chain(X.resource), bytes, {
      seen: new InMemorySeenUnits(),
      dek: () => X.dek,
      profile: sectionsCodecFor({ resourceId: X.resource, actor: me }),
    });
  for (const u of [bad, good]) w.server.inject(X.resource, u.bytes);
  return { X: X.resource, me, bad, good, receive };
}

describe("the rotation frontier with per-unit profiles (FlowOptions.profiles)", {
  timeout: 60_000,
}, () => {
  test("a unit carrying another actor's change stays out; the honest next unit counts and is accepted after", async () => {
    const w = await world(0);
    const { X, me, bad, good, receive } = await wrongActorSection(w);
    // Every receiver: A/1 refused (CHANGE_ACTOR_MISMATCH), A/2 accepted.
    expect((await receive(bad.bytes)).kind).toBe("local-failure");
    expect((await receive(good.bytes)).kind).toBe("accepted");
    const frontier = await rotate(w, X, { profiles: [sectionsUnitProfile] });
    expect(hasSequence(frontier, me, 1n)).toBe(false);
    expect(hasSequence(frontier, me, 2n)).toBe(true);
    expect((await receive(good.bytes)).kind).toBe("accepted");
  });

  test("without the profile, the frontier cannot tell: it counts A/1 and loses A/2 (the defect fixed above)", async () => {
    const w = await world(0);
    const { X, me } = await wrongActorSection(w);
    const frontier = await rotate(w, X);
    expect(hasSequence(frontier, me, 1n)).toBe(true);
    expect(hasSequence(frontier, me, 2n)).toBe(false);
  });

  test("the Identity Resource's rotation leaves out a unit the Identity Profile refuses", async () => {
    // An Identity Resource written through the real document (IdentityReplica), not a fake.
    const server = new MemoryCoordinator();
    const P = { ...node(server, party(1)), document: replicaPort };
    const created = await createIdentityResource({ ...P, url: URL, label: "laptop", roster: [] });
    if (created.kind !== "created") throw new Error(created.kind);
    const w = { server, P, I: created.identity, resources: [] } as unknown as World;
    const I = w.I;
    const chain = w.server.chain(I);
    const me = w.P.installation.signer.descriptor.principalId;
    const dek = (await heldDeks(w.P.secrets, chain)).get(String(chain.state.epoch.epoch));
    if (dek === undefined) throw new Error("no key");
    const mine = [...(w.server.hosted.get(toHex(I))?.units.values() ?? [])]
      .map((b) => parseDataUnit(b))
      .filter((u) => toHex(u.payload.actor) === toHex(me))
      .sort((x, y) => (x.payload.actorSeq < y.payload.actorSeq ? -1 : 1));
    const prev = mine.at(-1);
    const seq = (prev?.payload.actorSeq ?? 0n) + 1n;
    const junk = sealDataUnit(
      {
        resourceId: I,
        dataEpoch: chain.state.epoch.epoch,
        actorSeq: actorSequence(seq),
        prevDataUnitId: (prev?.signed.id ?? null) as DataUnitId | null,
        controlHead: chain.state.head,
      },
      new TextEncoder().encode("not an identity change"),
      dek,
      w.P.installation.signer,
    );
    w.server.inject(I, junk.bytes);
    const frontier = await rotate(w, I, { profiles: [identityUnitProfile] });
    expect(hasSequence(frontier, me, seq - 1n)).toBe(true);
    expect(hasSequence(frontier, me, seq)).toBe(false);
  });

  test("0.3.1's bare codecs are refused, never used as a weaker check", async () => {
    const w = await world(0);
    const X = await hostResource(w.server, w.P, SECTIONS_PROFILE_ID);
    const bare: DataProfileCodec<unknown> = {
      dataProfile: SECTIONS_PROFILE_ID,
      encode: (v: unknown) => v as Uint8Array,
      decode: (v: Uint8Array) => v,
    };
    const id = "rotate.legacy";
    await new OperationJournal(w.P.storage).begin({ id, kind: "rotate", createdAt: 1, intent: {} });
    const channel = await w.P.network.connect(w.P.installation.signer, URL);
    await expect(
      rotateAfter({
        ...w.P,
        dataProfiles: [bare],
        channel,
        resource: X.resource,
        operation: id,
        revokedAt: 0n,
      } as never),
    ).rejects.toThrow(TypeError);
    await expect(
      verifiedFrontier(channel, w.server.chain(X.resource), undefined, {
        deks: new Map(),
        profile: bare as never,
      }),
    ).rejects.toThrow(TypeError);
  });
});
