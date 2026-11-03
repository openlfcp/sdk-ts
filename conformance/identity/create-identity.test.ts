// createIdentityResource (IDENTITY-PROFILE-01 §5.1) with the real Identity
// Resource document: the initial change in the root's unit 1 is admitted by
// AI0, the fill change in unit 2 depends on it, and an installation that
// loads I from the coordinator sees the same document.

import {
  createIdentityResource,
  heldDeks,
  loadIdentityDocument,
  principalRefOf,
} from "@openlfcp/client";
import { dataEpoch, toBase64url } from "@openlfcp/core";
import { describe, expect, test } from "vitest";
import { MemoryCoordinator } from "../../packages/client/test/identity/memory-coordinator.js";
import { device, fill, party, URL } from "../../packages/client/test/identity/support.js";
import { replicaPort } from "./replica-port.js";

describe("createIdentityResource with IdentityReplica", () => {
  test("the coordinator's units rebuild the same valid document", async () => {
    const server = new MemoryCoordinator();
    const local = device();
    const P = party(1);
    const X = fill(9);
    const r = await createIdentityResource({
      installation: P,
      ...local,
      network: server.network(),
      url: URL,
      label: "laptop",
      platform: "linux",
      addedAt: "2026-11-04T00:00:00Z",
      roster: [
        {
          resource: X as never,
          entry: { profile: "org.example.v1", endpoints: [URL], coordinator: URL, name: "Notes" },
        },
      ],
      document: replicaPort,
      now: () => 0,
    });
    if (r.kind !== "created") throw new Error(r.kind);
    const v = (r.document as ReturnType<typeof replicaPort>).replica().validate();
    expect(v.usable).toBe(true);
    expect(v.problems).toEqual([]);
    expect(Object.keys(v.roster)).toEqual([toBase64url(X)]);
    expect(v.devices[principalRefOf(P.signer.descriptor.principalId)]).toEqual({
      label: "laptop",
      kind: 0,
      platform: "linux",
      added_at: "2026-11-04T00:00:00Z",
    });

    // Another installation reading I (e.g. B as a pairing device, §5.3 step 2).
    const other = replicaPort(r.identity, P.signer.descriptor.principalId);
    const channel = await server.network().connect(P.signer, URL);
    await loadIdentityDocument({
      channel,
      chain: r.chain,
      deks: await heldDeks(local.secrets, r.chain),
      doc: other,
    });
    expect(other.replica().heads()).toEqual(
      (r.document as ReturnType<typeof replicaPort>).replica().heads(),
    );
    expect(other.replica().validate()).toEqual(v);
    expect(r.chain.state.epoch.epoch).toBe(dataEpoch(0n));
  });
});
