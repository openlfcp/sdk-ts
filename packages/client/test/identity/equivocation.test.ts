import { dataEpoch, generateResourceId, type ResourceId, toHex } from "@openlfcp/core";
import { dekCommitment, generateResourceDEK, sha256 } from "@openlfcp/crypto";
import { parseDataUnit, sealDataUnit, signControlRecord } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks, loadIdentityDocument } from "../../src/identity/context.js";
import { principalRefOf } from "../../src/identity/document.js";
import { createIdentityResource } from "../../src/identity/resource.js";
import { FakeIdentityDocument } from "./fake-document.js";
import { MemoryCoordinator } from "./memory-coordinator.js";
import { device, party, URL } from "./support.js";

const OWNER = party(1);
function _raw() {
  const R: ResourceId = generateResourceId();
  const dek = generateResourceDEK();
  const records: Uint8Array[] = [];
  const add = (
    body: Parameters<typeof signControlRecord>[1],
    prev: Uint8Array | null,
    seq: bigint,
  ) => {
    const s = signControlRecord(
      { resourceId: R, controlSeq: seq, prevControlId: prev as never },
      body,
      OWNER.signer,
    );
    return s;
  };
  const g = add(
    {
      type: "GENESIS",
      dataProfile: "org.example.v1",
      owner: OWNER.signer.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), dek),
      endpoints: [{ url: URL, priority: 0n }],
      coordinatorUrl: URL,
    },
    null,
    0n,
  );
  records.push(g.bytes);
  const grant = (n: number, prev: Uint8Array, seq: bigint) =>
    add(
      {
        type: "CAPABILITY_GRANT",
        subject: party(n).signer.descriptor,
        abilities: [1n],
        delegable: [],
      },
      prev,
      seq,
    );
  return { R, dek, g, grant };
}

describe("loadIdentityDocument and equivocation (W §26.2)", () => {
  test("two units at one (actor, sequence) are both excluded, with their dependants", async () => {
    const server = new MemoryCoordinator();
    const local = device();
    const r = await createIdentityResource({
      installation: OWNER,
      ...local,
      network: server.network(),
      url: URL,
      label: "laptop",
      roster: [],
      document: () => new FakeIdentityDocument(),
      now: () => 0,
    });
    if (r.kind !== "created") throw new Error(r.kind);
    const deks = await heldDeks(local.secrets, r.chain);
    const unit2 = [...(server.hosted.get(toHex(r.identity))?.units.values() ?? [])].find(
      (b) => parseDataUnit(b).payload.actorSeq === 2n,
    ) as Uint8Array;
    const id2 = sha256(unit2);
    const put = (key: string, seq: bigint, previous: Uint8Array) => {
      const plaintext = new TextEncoder().encode(
        JSON.stringify({
          intents: [{ intent: "device.put", key, entry: { label: key, kind: 0 } }],
        }),
      );
      return sealDataUnit(
        {
          resourceId: r.identity,
          dataEpoch: dataEpoch(0n),
          actorSeq: seq as never,
          prevDataUnitId: previous as never,
          controlHead: r.chain.state.head,
        },
        plaintext,
        deks.get("0") as never,
        OWNER.signer,
      );
    };
    const x = put(principalRefOf(party(5).signer.descriptor.principalId), 3n, id2);
    const y = put(principalRefOf(party(6).signer.descriptor.principalId), 3n, id2);
    const z = put(principalRefOf(party(7).signer.descriptor.principalId), 4n, x.unitId);
    for (const u of [x, y, z]) server.inject(r.identity, u.bytes);
    const channel = await server.network().connect(OWNER.signer, URL);
    const doc = new FakeIdentityDocument();
    await loadIdentityDocument({ channel, chain: r.chain, deks, doc });
    expect([...doc.devices().keys()]).toEqual([
      principalRefOf(OWNER.signer.descriptor.principalId),
    ]);
  });
});
