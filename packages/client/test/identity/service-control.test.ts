import { type PrincipalId, toHex } from "@openlfcp/core";
import { describe, expect, test } from "vitest";
import { fetchDeks, loadIdentityDocument, syncChain } from "../../src/identity/context.js";
import { resourceRef } from "../../src/identity/document.js";
import {
  createServiceControl,
  SERVICE_CONTROL_PROFILE,
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
