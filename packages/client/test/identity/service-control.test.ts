import { dataUnitId, type PrincipalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, test } from "vitest";
import { fetchDeks, loadIdentityDocument, syncChain } from "../../src/identity/context.js";
import { resourceRef } from "../../src/identity/document.js";
import {
  createServiceControl,
  SERVICE_CONTROL_PROFILE,
  serviceControlPort,
  serviceControlRosterName,
  serviceControlSignerFacts,
} from "../../src/service-control.js";
import { party, URL } from "./support.js";
import { type Node, pair, world } from "./world.js";

// SERVICE-CONTROL-PROFILE-01 §1, §2.3, §11 (E-014): a managing client
// creates the control Resource C, owned by the root and listed in the
// roster; the signer facts its admission takes at a unit's control_ref.

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;

async function rosterOf(who: Node, I: Parameters<typeof syncChain>[2]) {
  const channel = await who.network.connect(who.installation.signer, URL);
  const chainI = await syncChain(who.storage, channel, I);
  const doc = who.document(I, id(1));
  await loadIdentityDocument({
    channel,
    chain: chainI,
    deks: await fetchDeks(who.storage, who.secrets, channel, chainI, who.installation),
    doc,
  });
  return doc.roster();
}

describe("createServiceControl", () => {
  test("the root creates C, owns it and lists it under the roster name of §11", async () => {
    const w = await world(0);
    const r = await createServiceControl({ ...w.P, url: URL, mac: "MacBook Air" });
    if (r.kind !== "created") throw new Error(r.kind);
    const chain = w.server.chain(r.resource);
    const g = chain.records[0]?.body;
    expect(g?.type === "GENESIS" && g.dataProfile).toBe(SERVICE_CONTROL_PROFILE);
    expect(g?.type === "GENESIS" && toHex(g.owner.principalId)).toBe(toHex(id(1)));
    expect(g?.type === "GENESIS" && g.deviceChain).toBeUndefined();
    const entry = (await rosterOf(w.P, w.I)).get(resourceRef(r.resource));
    expect(entry?.name).toBe("Reminders bridge · MacBook Air (needs Shared Tasks 0.8)");
    expect(entry?.profile).toBe(SERVICE_CONTROL_PROFILE);
    expect(r.initialize.intent).toBe("initialize");
    // Resumed: the same C and the same attempt, nothing created twice.
    const again = await createServiceControl({
      ...w.P,
      url: URL,
      mac: "MacBook Air",
      operation: r.operation,
    });
    expect(again.kind === "created" && toHex(again.resource)).toBe(toHex(r.resource));
    expect(again.kind === "created" && again.initialize).toEqual(r.initialize);
  });

  test("a personal device with 13 creates C for its root (IDENTITY §7.3)", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const r = await createServiceControl({ ...A, url: URL, mac: "Mac mini" });
    if (r.kind !== "created") throw new Error(r.kind);
    const g = w.server.chain(r.resource).records[0]?.body;
    expect(g?.type === "GENESIS" && toHex(g.owner.principalId)).toBe(toHex(id(1)));
    expect(g?.type === "GENESIS" && g.deviceChain !== undefined).toBe(true);
    expect((await rosterOf(w.P, w.I)).get(resourceRef(r.resource))?.name).toBe(
      serviceControlRosterName("Mac mini"),
    );
  });

  test("an Edit device cannot create C", async () => {
    const w = await world(0);
    const B = await pair(w, w.P, 3, "edit");
    const r = await createServiceControl({ ...B, url: URL, mac: "Mac" });
    expect(r.kind).toBe("not-owner-acting");
  });
});

describe("serviceControlSignerFacts (§2.3 at control_ref)", () => {
  test("the owner, and a bound device with its kind, root and standing", async () => {
    const w = await world(0);
    const A = await pair(w, w.P, 2, "full");
    const state = w.server.chain(w.I).state;
    expect(serviceControlSignerFacts(state, id(1))).toEqual({ owner: id(1), signer: id(1) });
    const facts = serviceControlSignerFacts(state, A.installation.signer.descriptor.principalId);
    expect(facts.device).toEqual({ kind: 0, root: id(1), boundInC: true, active: true });
    expect(serviceControlSignerFacts(state, id(9)).device).toBeUndefined();
  });
});

describe("serviceControlPort.acknowledged (SERVICE-CONTROL-PROFILE-01 §7.1, IDENTITY §9.1)", () => {
  const unit = (n: number) => dataUnitId(new Uint8Array(32).fill(n));
  /** A port whose entry was created by changes carried by `creators` (hash → units), `acked` the units ACKed. */
  function portWith(creators: Record<string, readonly number[]>, acked: readonly number[]) {
    const resource = resourceId(new Uint8Array(32).fill(9));
    const asked: string[] = [];
    const port = serviceControlPort({
      resource,
      client: {
        commit: async () => ({}) as never,
        statusSnapshot: async () => ({ batches: [] }) as never,
        unitAcknowledged: async (r, u) => {
          expect(toHex(r)).toBe(toHex(resource));
          asked.push(toHex(u));
          return acked.some((n) => toHex(unit(n)) === toHex(u));
        },
      },
      profile: {
        state: () => ({ approvals: {}, requests: {}, pairing: {}, cancels: {} }),
        replica: {
          creatorsOf: () =>
            Object.keys(creators).map((hash) => ({
              hash,
              signer: id(1),
              writerClass: "root" as const,
            })),
          requestHistory: () => [],
        },
        unitsOf: (hash) => (creators[hash] ?? []).map(unit),
      },
    });
    return { port, asked };
  }

  test("only an acknowledged unit of a creating change counts", async () => {
    const key = "p:x";
    expect(await portWith({ a: [1] }, []).port.acknowledged("approvals", key)).toBe(false);
    expect(await portWith({ a: [1] }, [1]).port.acknowledged("approvals", key)).toBe(true);
    // Staged, not committed yet: no unit carries it.
    expect(await portWith({ a: [] }, [1]).port.acknowledged("approvals", key)).toBe(false);
    // No value.
    expect(await portWith({}, [1]).port.acknowledged("approvals", key)).toBe(false);
    // Two equal approvals (§5 rule 3): another client's acknowledged one counts.
    const two = portWith({ a: [1], b: [3] }, [3]);
    expect(await two.port.acknowledged("approvals", key)).toBe(true);
    expect(two.asked).toEqual([toHex(unit(1)), toHex(unit(3))]);
  });
});
