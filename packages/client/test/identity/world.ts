import { dataEpoch, generateResourceId, type ResourceId, toHex } from "@openlfcp/core";
import { dekCommitment, generateResourceDEK } from "@openlfcp/crypto";
import { signControlRecord, validateControlChain } from "@openlfcp/wire";
import {
  heldDeks,
  type Installation,
  loadIdentityDocument,
  sealIdentityUnit,
  storeDek,
  syncChain,
} from "../../src/identity/context.js";
import {
  type FlowOptions,
  leafPayload,
  type MaskPreset,
  registerDevice,
  signChain,
} from "../../src/identity/devices.js";
import { resourceRef } from "../../src/identity/document.js";
import {
  approvePairing,
  createPairingSession,
  pairingRequests,
} from "../../src/identity/pairing.js";
import { completePairing, requestPairing } from "../../src/identity/pairing-request.js";
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

/** Pairs `who` through `approver` with a preset; returns the new installation, approved and complete. */
export async function pair(
  w: { server: MemoryCoordinator },
  approver: Node,
  who: number,
  preset: MaskPreset,
  options: { kind?: 0 | 1; scope?: readonly ResourceId[] } = {},
): Promise<Node> {
  const s = await createPairingSession(approver);
  if (s.kind !== "created") throw new Error(`session: ${s.kind}`);
  const n = node(w.server, party(who));
  const req = await requestPairing({
    ...n,
    link: s.link,
    label: `device ${who}`,
    kind: options.kind ?? 0,
    ...(options.scope === undefined ? {} : { scope: options.scope }),
  });
  if (req.kind !== "requested") throw new Error(`request: ${req.kind}`);
  const [review] = await pairingRequests({ ...approver, session: s.session });
  if (review === undefined) throw new Error("no request");
  const a = await approvePairing({
    ...approver,
    review,
    preset,
    ...(options.scope === undefined ? {} : { scope: options.scope }),
  });
  if (a.kind !== "approved") throw new Error(`approval: ${a.kind}`);
  const done = await completePairing({ ...n, operation: req.operation });
  if (done.kind !== "approved" || done.certificate === null)
    throw new Error(`complete: ${done.kind}`);
  return n;
}

/** Writes a roster entry into I as `writer` (a managing installation). */
export async function addToRoster(
  writer: Node,
  I: ResourceId,
  resource: ResourceId,
  entry: { profile: string; endpoints: string[]; coordinator: string },
) {
  const channel = await writer.network.connect(writer.installation.signer, URL);
  const chain = await syncChain(writer.storage, channel, I);
  const doc = writer.document(I, chain.state.owner.principalId);
  const deks = await heldDeks(writer.secrets, chain);
  const load = await loadIdentityDocument({ channel, chain, deks, doc });
  const bytes = await sealIdentityUnit({
    storage: writer.storage,
    chain,
    deks,
    signer: writer.installation.signer,
    doc,
    latest: load.latest,
    intents: [{ intent: "roster.put", key: resourceRef(resource), entry }],
  });
  const answer = await channel.putDataUnit(I, bytes);
  if (answer.kind !== "ack") throw new Error(answer.code);
}

/** The root re-certifies `who` directly (same kind, mask and scope, a new serial) in I only. */
export async function recertifyInI(
  w: Awaited<ReturnType<typeof world>>,
  who: number,
  kind: 0 | 1,
  mask: readonly bigint[],
  scope: Uint8Array[],
) {
  const channel = await w.P.network.connect(w.P.installation.signer, URL);
  const I = await syncChain(w.P.storage, channel, w.I);
  const leaf = leafPayload(
    party(1).signer.descriptor.principalId,
    party(who).signer.descriptor,
    kind,
    mask,
    scope as never,
  );
  const chain = signChain(I.state, w.P.installation.signer, leaf);
  const r = await registerDevice({ ...w.P, chain, targets: [{ resource: w.I, url: URL }] });
  if (r.results[0]?.status !== "registered")
    throw new Error(`re-certification: ${r.results[0]?.status}`);
}
