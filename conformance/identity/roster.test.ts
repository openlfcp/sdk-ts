// addToRoster with the real Identity Resource document (IdentityReplica):
// a Resource created after pairing reaches the human's other devices
// through the roster (IDENTITY-PROFILE-01 §2.1, §6, §7.1, §9).
import {
  addToRoster,
  createIdentityResource,
  fetchDeks,
  loadIdentityDocument,
  reconcileDevices,
  resourceRef,
  syncChain,
} from "@openlfcp/client";
import { toHex } from "@openlfcp/core";
import { parseDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { party, URL } from "../../packages/client/test/identity/support.js";
import { hostResource, type Node, node, pair } from "../../packages/client/test/identity/world.js";
import { replicaPort } from "./replica-port.js";

async function setup() {
  const server = new MemoryCoordinator();
  const P = { ...node(server, party(1)), document: replicaPort } as unknown as Node;
  const created = await createIdentityResource({ ...P, url: URL, label: "laptop", roster: [] });
  if (created.kind !== "created") throw new Error(created.kind);
  const A = await pair({ server }, P, 2, "full", { document: replicaPort as never });
  return { server, P, A, I: created.identity };
}

/** The roster as `who` reads it from the coordinator, with the real document. */
async function rosterOf(who: Node, I: Uint8Array) {
  const channel = await who.network.connect(who.installation.signer, URL);
  const chain = await syncChain(who.storage, channel, I as never);
  const doc = replicaPort(I as never, party(1).signer.descriptor.principalId);
  const deks = await fetchDeks(who.storage, who.secrets, channel, chain, who.installation);
  await loadIdentityDocument({ channel, chain, deks, doc });
  const v = doc.replica().validate();
  expect(v.problems).toEqual([]);
  return v.roster;
}

describe("addToRoster with IdentityReplica", { timeout: 120_000 }, () => {
  test("a Resource created after pairing reaches the other device through the roster", async () => {
    const { server, P, A, I } = await setup();
    const Y = await hostResource(server, P);
    const added = await addToRoster({
      ...P,
      resource: Y.resource,
      url: URL,
      name: "Later section",
    });
    expect(added.kind).toBe("added");
    expect((await rosterOf(A, I))[resourceRef(Y.resource)]).toEqual({
      profile: Y.entry.profile,
      endpoints: [URL],
      coordinator: URL,
      name: "Later section",
    });
    // Reconciliation from the roster registers A there and keys it (§7.1).
    await reconcileDevices(P);
    expect(
      server.chain(Y.resource).state.devices.get(toHex(party(2).signer.descriptor.principalId))
        ?.registered,
    ).toBe(true);
    // Another device asking again finds it present and writes nothing.
    const before = server.unitsOf(I).length;
    const again = await addToRoster({ ...A, resource: Y.resource, entry: Y.entry });
    expect(again.kind).toBe("present");
    expect(server.unitsOf(I).length).toBe(before);
  });

  test("a unit refused as stale is written again; another refusal leaves the operation open", async () => {
    const { server, P, I } = await setup();
    const Y = await hostResource(server, P);
    const mine = (e: { op: string; resource: Uint8Array; bytes: Uint8Array }) =>
      e.op === "data-unit" &&
      toHex(e.resource) === toHex(I) &&
      toHex(parseDataUnit(e.bytes).payload.actor) === toHex(party(1).signer.descriptor.principalId);
    let once = false;
    server.fault = (e) => {
      if (once || !mine(e)) return undefined;
      once = true;
      return { nack: "STALE_DATA_EPOCH" };
    };
    expect((await addToRoster({ ...P, resource: Y.resource, url: URL })).kind).toBe("added");

    const Z = await hostResource(server, P);
    server.fault = (e) => (mine(e) ? { nack: "QUOTA_EXCEEDED" } : undefined);
    const refused = await addToRoster({ ...P, resource: Z.resource, url: URL });
    if (refused.kind !== "document-incomplete") throw new Error(refused.kind);
    expect(refused.code).toBe("QUOTA_EXCEEDED");
    server.fault = () => undefined;
    const resumed = await addToRoster({ ...P, resource: Z.resource, operation: refused.operation });
    expect(resumed.kind).toBe("added");
    expect(Object.keys(await rosterOf(P, I)).sort()).toEqual(
      [resourceRef(Y.resource), resourceRef(Z.resource)].sort(),
    );
  });

  test("a Read device cannot write the roster", async () => {
    const { server, P } = await setup();
    const R3 = await pair({ server }, P, 3, "read", { document: replicaPort as never });
    const Y = await hostResource(server, P);
    expect((await addToRoster({ ...R3, resource: Y.resource, entry: Y.entry })).kind).toBe(
      "needs-writer",
    );
  });
});
