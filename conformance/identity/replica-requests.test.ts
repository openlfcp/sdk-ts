// Request provenance with the real Identity Resource document (review
// 11.3): two pairing devices write on one Control Head, the second request
// causally after the first and by a pairing device whose ID sorts first, so
// the replica holds it until the first arrives. Each request is still
// attributed to its own pairing device (IDENTITY-PROFILE-01 §5.3 step 4).

import {
  createIdentityResource,
  createPairingSession,
  type PairingSessionResult,
  pairingRequests,
  requestPairing,
} from "@openlfcp/client";
import { toHex } from "@openlfcp/core";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { party, URL } from "../../packages/client/test/identity/support.js";
import { node } from "../../packages/client/test/identity/world.js";
import { replicaPort } from "./replica-port.js";

type Created = Extract<PairingSessionResult, { kind: "created" }>;

describe("pairing requests with IdentityReplica", { timeout: 120_000 }, () => {
  test("a held request admitted later keeps its own writer", async () => {
    const server = new MemoryCoordinator();
    const real = (n: number) => ({ ...node(server, party(n)), document: replicaPort }) as never;
    const P = real(1) as ReturnType<typeof node>;
    const created = await createIdentityResource({ ...P, url: URL, label: "laptop", roster: [] });
    if (created.kind !== "created") throw new Error(created.kind);
    // Two sessions where the later pairing device sorts before the earlier one.
    let first: Created | undefined;
    let last: Created | undefined;
    for (let i = 0; last === undefined; i++) {
      if (i > 24) throw new Error("no ordering found");
      const s = await createPairingSession(P);
      if (s.kind !== "created") throw new Error(s.kind);
      if (first !== undefined && toHex(s.pairingDevice) < toHex(first.pairingDevice)) last = s;
      else if (first === undefined || toHex(s.pairingDevice) > toHex(first.pairingDevice))
        first = s;
    }
    const B1 = real(3) as ReturnType<typeof node>;
    const B2 = real(4) as ReturnType<typeof node>;
    expect(
      (await requestPairing({ ...B1, link: (first as Created).link, label: "one", kind: 0 })).kind,
    ).toBe("requested");
    expect((await requestPairing({ ...B2, link: last.link, label: "two", kind: 0 })).kind).toBe(
      "requested",
    );
    expect(
      (await pairingRequests({ ...P, session: (first as Created).session })).map((r) => r.label),
    ).toEqual(["one"]);
    expect((await pairingRequests({ ...P, session: last.session })).map((r) => r.label)).toEqual([
      "two",
    ]);
  });
});
