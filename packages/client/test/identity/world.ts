import { dataEpoch, generateResourceId, type ResourceId, toHex } from "@openlfcp/core";
import { dekCommitment, generateResourceDEK } from "@openlfcp/crypto";
import { signControlRecord, validateControlChain } from "@openlfcp/wire";
import { type Installation, storeDek } from "../../src/identity/context.js";
import type { FlowOptions } from "../../src/identity/devices.js";
import { createIdentityResource } from "../../src/identity/resource.js";
import { FakeIdentityDocument } from "./fake-document.js";
import { MemoryCoordinator } from "./memory-coordinator.js";
import { device, party, URL } from "./support.js";

/** One installation of the test world: its Principal, storage and secrets, and its flow options. */
export interface Node extends FlowOptions {
  readonly document: (r: ResourceId, root: Uint8Array) => FakeIdentityDocument;
}

export function node(server: MemoryCoordinator, who: Installation, local = device()): Node {
  return {
    installation: who,
    ...local,
    network: server.network(),
    now: () => 1,
    document: () => new FakeIdentityDocument(),
  };
}

/** A raw Resource owned by `owner`, hosted, its chain and epoch-0 DEK in the owner's storage. */
export async function hostResource(
  server: MemoryCoordinator,
  owner: Node,
  profile = "org.example.v1",
) {
  const R = generateResourceId();
  const dek = generateResourceDEK();
  const genesis = signControlRecord(
    { resourceId: R, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: profile,
      owner: owner.installation.signer.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), dek),
      endpoints: [{ url: URL, priority: 0n }],
      coordinatorUrl: URL,
    },
    owner.installation.signer,
  );
  const chain = validateControlChain([genesis.bytes]);
  if (chain.kind !== "linear") throw new Error(chain.kind);
  await storeDek(owner.storage, owner.secrets, chain, dataEpoch(0n), dek);
  server.seed([genesis.bytes]);
  return { resource: R, entry: { profile, endpoints: [URL], coordinator: URL } };
}

/** Root P with an Identity Resource whose roster lists `n` raw Resources. */
export async function world(n = 1) {
  const server = new MemoryCoordinator();
  const P = node(server, party(1));
  const resources = [];
  for (let i = 0; i < n; i++) resources.push(await hostResource(server, P));
  const created = await createIdentityResource({
    ...P,
    url: URL,
    label: "laptop",
    roster: resources,
  });
  if (created.kind !== "created") throw new Error(created.kind);
  return { server, P, I: created.identity, resources: resources.map((r) => r.resource) };
}

export const hex = (b: Uint8Array) => toHex(b);
