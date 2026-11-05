// Installations of the live identity tests (LFCP-04-412): a Principal with
// its own in-memory storage and secrets on the real WebSocket network, the
// Identity Resource document over IdentityReplica, and a raw Resource it
// hosts on the reference server.

import { connectionNetwork, type IdentityNetwork, storeDek, syncChain } from "@openlfcp/client";
import { dataEpoch, generateResourceId, type ResourceId } from "@openlfcp/core";
import { dekCommitment, generateResourceDEK } from "@openlfcp/crypto";
import { InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import { signControlRecord, validateControlChain } from "@openlfcp/wire";
import { party } from "../../packages/client/test/identity/support.js";
import { replicaPort } from "../identity/replica-port.js";
import { sleep } from "./harness.js";

const network = (): IdentityNetwork =>
  connectionNetwork({ now: () => Date.now(), timeout: () => sleep(20_000) });

/** One installation: its Principal, its own storage and secrets, the real network. */
export function installation(n: number) {
  return {
    installation: party(n),
    storage: new InMemoryLfcpStorage(),
    secrets: new InMemorySecretStore(),
    network: network(),
    now: () => Date.now(),
    document: replicaPort,
  };
}
export type Node = ReturnType<typeof installation>;

/** A raw Resource owned and hosted by `owner`, its epoch-0 DEK in the owner's secrets. */
export async function hostResource(owner: Node, url: string, name = "X") {
  const R = generateResourceId();
  const dek = generateResourceDEK();
  const genesis = signControlRecord(
    { resourceId: R, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: "org.lfcp.test.raw.v1",
      owner: owner.installation.signer.descriptor,
      dekCommitment: dekCommitment(R, dataEpoch(0n), dek),
      endpoints: [{ url, priority: 0n }],
      coordinatorUrl: url,
    },
    owner.installation.signer,
  );
  const chain = validateControlChain([genesis.bytes]);
  if (chain.kind !== "linear") throw new Error(chain.kind);
  const channel = await owner.network.connect(owner.installation.signer, url);
  try {
    const hosted = await channel.host(genesis.bytes);
    if (hosted.kind !== "ack") throw new Error(`RESOURCE_HOST: ${JSON.stringify(hosted)}`);
  } finally {
    channel.close();
  }
  await storeDek(owner.storage, owner.secrets, chain, dataEpoch(0n), dek);
  return {
    resource: R,
    entry: { profile: "org.lfcp.test.raw.v1", endpoints: [url], coordinator: url, name },
  };
}

export async function chainOf(who: Node, url: string, resource: ResourceId) {
  const channel = await who.network.connect(who.installation.signer, url);
  try {
    return await syncChain(who.storage, channel, resource);
  } finally {
    channel.close();
  }
}
