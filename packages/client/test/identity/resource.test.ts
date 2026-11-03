import { toHex } from "@openlfcp/core";
import { parseDataUnit } from "@openlfcp/wire";
import { describe, expect, test } from "vitest";
import { heldDeks } from "../../src/identity/context.js";
import { principalRefOf, resourceRef } from "../../src/identity/document.js";
import { OperationJournal } from "../../src/identity/journal.js";
import {
  createIdentityResource,
  localIdentityResource,
  resumeIdentityCreation,
} from "../../src/identity/resource.js";
import { FakeIdentityDocument } from "./fake-document.js";
import { MemoryCoordinator } from "./memory-coordinator.js";
import { device, fill, party, URL } from "./support.js";

const P = party(1);
const X = {
  resource: fill(9) as never,
  entry: { profile: "org.example.v1", endpoints: [URL], coordinator: URL },
};

function options(server: MemoryCoordinator, local = device()) {
  const docs: FakeIdentityDocument[] = [];
  return {
    local,
    docs,
    options: {
      installation: P,
      storage: local.storage,
      secrets: local.secrets,
      network: server.network(),
      url: URL,
      label: "laptop",
      roster: [X],
      document: () => {
        const d = new FakeIdentityDocument();
        docs.push(d);
        return d;
      },
      now: () => 1,
    },
  };
}

describe("createIdentityResource (IDENTITY-PROFILE-01 §5.1)", () => {
  test("hosts I, writes the initial change in unit 1 and the fill change in unit 2", async () => {
    const server = new MemoryCoordinator();
    const { options: o, local } = options(server);
    const r = await createIdentityResource(o);
    expect(r.kind).toBe("created");
    if (r.kind !== "created") return;
    const chain = server.chain(r.identity);
    expect(chain.state.dataProfile).toBe("org.openlfcp.identity.v1");
    expect(toHex(chain.state.owner.principalId)).toBe(toHex(P.signer.descriptor.principalId));
    expect(
      chain.records[0]?.body.type === "GENESIS" && chain.records[0].body.deviceChain,
    ).toBeFalsy();
    const units = server.unitsOf(r.identity).sort((a, b) => Number(a.actorSeq - b.actorSeq));
    expect(units.map((u) => u.actorSeq)).toEqual([1n, 2n]);
    expect(units[1]?.prevDataUnitId).not.toBeNull();
    expect(r.document.initialized()).toBe(true);
    expect([...r.document.roster().keys()]).toEqual([resourceRef(X.resource)]);
    expect(r.document.devices().get(principalRefOf(P.signer.descriptor.principalId))).toEqual({
      label: "laptop",
      kind: 0,
    });
    expect(toHex((await localIdentityResource(local.storage)) as never)).toBe(toHex(r.identity));
    expect((await heldDeks(local.secrets, chain)).has("0")).toBe(true);
    expect((await new OperationJournal(local.storage).list({ status: "open" })).length).toBe(0);
  });

  test("stops when the default server does not advertise identity-01 (§5.1 step 1)", async () => {
    const server = new MemoryCoordinator();
    server.extensions = [];
    expect((await createIdentityResource(options(server).options)).kind).toBe("unsupported");
    expect(server.hosted.size).toBe(0);
  });

  for (const op of ["host", "data-unit"] as const)
    for (const fault of ["drop-request", "drop-answer"] as const)
      for (const nth of op === "host" ? [1] : [1, 2])
        test(`resumes after a ${fault} of ${op} ${nth} with the journaled exact bytes`, async () => {
          const server = new MemoryCoordinator();
          let seen = 0;
          server.fault = (e) => (e.op === op && ++seen === nth ? fault : undefined);
          const first = options(server);
          const r1 = await createIdentityResource(first.options);
          expect(r1.kind).toBe("unavailable");
          // Restart: the same storage and secrets, a fresh document port.
          const again = options(server, first.local);
          const r2 = await createIdentityResource(again.options);
          expect(r2.kind).toBe("created");
          if (r2.kind !== "created") return;
          expect(server.hosted.size).toBe(1);
          const units = server.unitsOf(r2.identity);
          expect(units.map((u) => u.actorSeq).sort()).toEqual([1n, 2n]);
          // The resumed document was loaded from the coordinator's units.
          expect(r2.document.initialized()).toBe(true);
          expect(r2.document.roster().size).toBe(1);
          // Every re-sent unit carried the journaled bytes: one set of bytes per sequence.
          const bySeq = new Map<string, Set<string>>();
          for (const u of server.uploads.filter((x) => x.op === "data-unit")) {
            const seq = String(parseDataUnit(u.bytes).payload.actorSeq);
            bySeq.set(seq, (bySeq.get(seq) ?? new Set()).add(toHex(u.bytes)));
          }
          expect([...bySeq.values()].every((v) => v.size === 1)).toBe(true);
          expect(server.uploads.filter((u) => u.op === "host").length).toBe(op === "host" ? 2 : 1);
        });

  test("resumeIdentityCreation is a no-op on a finished operation's units", async () => {
    const server = new MemoryCoordinator();
    const { options: o } = options(server);
    const r = await createIdentityResource(o);
    if (r.kind !== "created") throw new Error(r.kind);
    const again = await resumeIdentityCreation(o, r.operation);
    expect(again.kind).toBe("created");
    expect(server.unitsOf(r.identity).length).toBe(2);
  });
});
