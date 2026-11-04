// A display write of the identity flows racing another writer, with the real
// Identity Resource document (IdentityReplica; review of sdk-ts#17, P2):
// between the read that decides to write and the read the unit is built on,
// another managing device writes the same effect, or deletes the entry. The
// flow then sends nothing and completes; it never throws or stops short.
import {
  approvePairing,
  createIdentityResource,
  createPairingSession,
  fetchDeks,
  type IdentityIntent,
  loadIdentityDocument,
  OperationJournal,
  pairingRequests,
  principalRefOf,
  reconcileDevices,
  requestPairing,
  sealIdentityUnit,
  syncChain,
} from "@openlfcp/client";
import { bytesEqual, type PrincipalId, type ResourceId } from "@openlfcp/core";
import { deviceFingerprint } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { party, URL } from "../../packages/client/test/identity/support.js";
import { hostResource, type Node, node, pair } from "../../packages/client/test/identity/world.js";
import { replicaPort } from "./replica-port.js";

const id = (n: number) => party(n).signer.descriptor.principalId as PrincipalId;
const ROOT = id(1);

/**
 * Root P, its Identity Resource with `roster` raw Resources, and A (device
 * 2, full, managing), all on IdentityReplica. Two ways for another writer's
 * unit to land between a flow's two reads of the document:
 * - `arm(bytes)`: injected when P's document factory is first called from a
 *   unit's `build` (the second read);
 * - `armAfterRead(callers, write)`: `write` runs right after the Data Units
 *   of a read whose two callers are `callers` ("f/g": loadIdentityDocument
 *   called by f, called by g; the first read) are fetched, so that read does
 *   not see it and the next one does.
 */
async function realWorld(roster = 0) {
  const server = new MemoryCoordinator();
  let race: (() => void) | undefined;
  let after: { readonly caller: string; readonly write: () => Promise<void> } | undefined;
  const network = server.network();
  const P: Node = {
    ...node(server, party(1)),
    network: {
      connect: async (signer, url) => {
        const c = await network.connect(signer, url);
        return {
          ...c,
          dataUnits: async (r, ranges) => {
            const units = await c.dataUnits(r, ranges);
            const stack = new Error().stack ?? "";
            // The two functions above loadIdentityDocument, e.g. "current/markRevoked".
            const m =
              /at (?:async )?loadIdentityDocument[^\n]*\n\s+at (?:async )?(?:Object\.)?(\w+)[^\n]*\n\s+at (?:async )?(?:Object\.)?(\w+)/.exec(
                stack,
              );
            const caller = m === null ? undefined : `${m[1]}/${m[2]}`;
            if (after !== undefined && caller === after.caller) {
              const { write } = after;
              after = undefined;
              await write();
            }
            return units;
          },
        };
      },
    },
    document: (r: ResourceId, root: PrincipalId) => {
      if (race !== undefined && /\bbuild\b/.test(new Error().stack ?? "")) {
        const run = race;
        race = undefined;
        run();
      }
      return replicaPort(r, root) as never;
    },
  };
  const resources = [];
  for (let i = 0; i < roster; i++) resources.push(await hostResource(server, P as never));
  const created = await createIdentityResource({
    ...P,
    url: URL,
    label: "laptop",
    roster: resources,
  });
  if (created.kind !== "created") throw new Error(created.kind);
  const I = created.identity;
  const A = await pair({ server }, P, 2, "full", { document: replicaPort as never });
  return {
    server,
    P,
    A,
    I,
    arm: (bytes: Uint8Array) => {
      race = () => server.inject(I, bytes);
    },
    armAfterRead: (caller: string, write: () => Promise<void>) => {
      after = { caller, write };
    },
    armed: () => race !== undefined || after !== undefined,
  };
}

/** `who`'s view of I's document. */
async function open(server: MemoryCoordinator, who: Node, I: ResourceId) {
  const channel = await server.network().connect(who.installation.signer, URL);
  const chain = await syncChain(who.storage, channel, I);
  const doc = replicaPort(I, ROOT);
  const deks = await fetchDeks(who.storage, who.secrets, channel, chain, who.installation);
  const load = await loadIdentityDocument({ channel, chain, deks, doc });
  return { channel, chain, deks, doc, load };
}

/** A unit of `who` in I carrying `intents`, signed now and not sent. */
async function unitOf(
  server: MemoryCoordinator,
  who: Node,
  I: ResourceId,
  intents: IdentityIntent[],
) {
  const v = await open(server, who, I);
  return sealIdentityUnit({
    storage: who.storage,
    chain: v.chain,
    deks: v.deks,
    signer: who.installation.signer,
    doc: v.doc,
    latest: v.load.latest,
    intents,
  });
}

/** P's Data Units to I. */
const rootUnits = (server: MemoryCoordinator, I: ResourceId) =>
  server.unitsOf(I).filter((u) => bytesEqual(u.actor, ROOT)).length;

/** Device 3 approved in I's chain by P, its device entry refused and never written. */
async function withoutEntry(w: Awaited<ReturnType<typeof realWorld>>) {
  const s = await createPairingSession(w.P);
  if (s.kind !== "created") throw new Error(s.kind);
  const B = { ...node(w.server, party(3)), document: replicaPort as never };
  const req = await requestPairing({ ...B, link: s.link, label: "device 3", kind: 0 });
  if (req.kind !== "requested") throw new Error(req.kind);
  const [review] = await pairingRequests({ ...w.P, session: s.session });
  if (review === undefined) throw new Error("no request");
  w.server.fault = (e) =>
    e.op === "data-unit" && bytesEqual(e.signer.descriptor.principalId, ROOT)
      ? { nack: "AUTHORIZATION_FAILED" }
      : undefined;
  const a = await approvePairing({ ...w.P, review, preset: "edit" });
  w.server.fault = () => undefined;
  if (a.kind !== "document-incomplete") throw new Error(`approval: ${a.kind}`);
}

describe("identity display writes racing another writer (IdentityReplica)", {
  timeout: 120_000,
}, () => {
  test("reconcile: A writes the missing entry between the two reads; nothing is sent, the run is done", async () => {
    const w = await realWorld();
    await withoutEntry(w);
    const key = principalRefOf(id(3));
    w.arm(
      await unitOf(w.server, w.A, w.I, [
        { intent: "device.put", key, entry: { label: "phone", kind: 0 } },
      ]),
    );
    const before = rootUnits(w.server, w.I);
    const r = await reconcileDevices({ ...w.P, only: [w.I] });
    expect(w.armed()).toBe(false);
    expect(r.document).toEqual({ state: "complete" });
    expect(rootUnits(w.server, w.I)).toBe(before);
    expect((await new OperationJournal(w.P.storage).load(r.operation)).status).toBe("done");
    expect((await open(w.server, w.P, w.I)).doc.devices().get(key)?.label).toBe("phone");
  });

  test("reconcile: the entry written meanwhile, found when rebuilding after STALE_DATA_EPOCH", async () => {
    const w = await realWorld();
    await withoutEntry(w);
    const key = principalRefOf(id(3));
    const bytes = await unitOf(w.server, w.A, w.I, [
      { intent: "device.put", key, entry: { label: "phone", kind: 0 } },
    ]);
    let stale = false;
    w.server.fault = (e) => {
      if (stale || e.op !== "data-unit" || !bytesEqual(e.signer.descriptor.principalId, ROOT))
        return undefined;
      stale = true;
      w.server.inject(w.I, bytes);
      return { nack: "STALE_DATA_EPOCH" };
    };
    const r = await reconcileDevices({ ...w.P, only: [w.I] });
    w.server.fault = () => undefined;
    expect(stale).toBe(true);
    expect(r.document).toEqual({ state: "complete" });
    expect((await new OperationJournal(w.P.storage).load(r.operation)).status).toBe("done");
    const doc = (await open(w.server, w.P, w.I)).doc;
    expect(doc.devices().get(key)?.label).toBe("phone");
    expect(doc.devices().get(key)?.label).not.toBe(deviceFingerprint(id(3)));
  });
});
