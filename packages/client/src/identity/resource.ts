import {
  dataEpoch,
  fromHex,
  generateResourceId,
  type PrincipalId,
  type ResourceId,
  resourceId,
  secureRandom,
  toHex,
} from "@openlfcp/core";
import { dekCommitment, generateResourceDEK } from "@openlfcp/crypto";
import type { SecretStore } from "@openlfcp/storage";
import { signControlRecord, validateControlChain } from "@openlfcp/wire";
import { createDataUnit } from "../data-unit.js";
import {
  heldDeks,
  type IdentityStorage,
  type Installation,
  loadIdentityDocument,
  runUnitPhase,
  storeDek,
  syncChain,
} from "./context.js";
import {
  IDENTITY_PROFILE,
  type IdentityDocumentPort,
  type IdentityIntent,
  identityPlaintextCodec,
  principalRefOf,
  type RosterEntryValue,
  resourceRef,
} from "./document.js";
import {
  type JournalOperation,
  type JournalPhase,
  newOperationId,
  OperationJournal,
  phaseOf,
} from "./journal.js";
import {
  ChannelPool,
  IDENTITY_EXTENSION,
  type IdentityNetwork,
  IdentityUnavailable,
} from "./network.js";
import type { LinearChain } from "./phases.js";

/**
 * Creating the Identity Resource of an existing installation
 * (IDENTITY-PROFILE-01 §5.1), on the first "Add my other device…".
 *
 * The installation's Principal `P` becomes the root: Genesis with owner `P`
 * (no field 5), profile org.openlfcp.identity.v1, the default server as
 * route and coordinator; RESOURCE_HOST; then the initial change (§2.2) in
 * the root's Data Unit with actor sequence 1 and the fill change (roster
 * from the local Resource list, `devices[p:<P>]`) in sequence 2. The
 * Genesis, both units and the epoch-0 DEK are persisted before anything is
 * sent, and re-sent as exact bytes after a crash: the initial change is
 * never created twice (§2.2). A run that cannot obtain actor sequence 1
 * for the new Resource abandons it and creates another.
 */

const IDENTITY_MARK = "identity:resource";

/** The Identity Resource recorded as this installation's identity (W §86), if any. */
export async function localIdentityResource(
  storage: Pick<IdentityStorage, "localMarks">,
): Promise<ResourceId | undefined> {
  const v = await storage.localMarks.get(IDENTITY_MARK);
  return v === undefined ? undefined : resourceId(fromHex(v));
}

/** Records `I` as this installation's identity. */
export async function setLocalIdentityResource(
  storage: Pick<IdentityStorage, "commit">,
  identity: ResourceId,
): Promise<void> {
  const r = await storage.commit([
    { op: "put-local-mark", key: IDENTITY_MARK, value: toHex(identity) },
  ]);
  if (!r.ok) throw new Error(`the identity was not recorded: ${r.reason}`);
}

/** The document port of an Identity Resource, made once its ID and root are known. */
export type IdentityDocumentFactory = (
  identity: ResourceId,
  root: PrincipalId,
) => IdentityDocumentPort;

export interface CreateIdentityResourceOptions {
  /** The installation `P`, a root without devices (W §7.2 N1). */
  readonly installation: Installation;
  readonly storage: IdentityStorage;
  readonly secrets: SecretStore;
  readonly network: IdentityNetwork;
  /** The default server: route, coordinator and host of `I`. */
  readonly url: string;
  /** This installation's label for `devices[p:<P>]`. */
  readonly label: string;
  readonly platform?: string;
  /** The local Resource list for the roster. */
  readonly roster: readonly { readonly resource: ResourceId; readonly entry: RosterEntryValue }[];
  readonly document: IdentityDocumentFactory;
  /** RFC 3339 UTC time for `added_at`; omitted when absent. */
  readonly addedAt?: string;
  readonly now: () => number;
}

export type CreatedIdentityResource =
  | {
      readonly kind: "created";
      readonly identity: ResourceId;
      readonly chain: LinearChain;
      readonly document: IdentityDocumentPort;
      readonly operation: string;
    }
  /** §5.1 step 1: the default server's READY does not list identity-01. */
  | { readonly kind: "unsupported" }
  /** The coordinator refused hosting or a unit: the operation is abandoned. */
  | { readonly kind: "refused"; readonly code: string }
  /** The coordinator could not be reached: resume with resumeIdentityCreation. */
  | { readonly kind: "unavailable"; readonly operation: string; readonly reason: string };

/** §5.1: creates and hosts `I`, journaled; resumes an open creation first. */
export async function createIdentityResource(
  options: CreateIdentityResourceOptions,
): Promise<CreatedIdentityResource> {
  const journal = new OperationJournal(options.storage);
  const open = (await journal.list({ kind: "create-identity", status: "open" }))[0];
  if (open !== undefined) return resumeIdentityCreation(options, open.id);
  const pool = new ChannelPool(options.network);
  try {
    const channel = await pool.get(options.installation.signer, options.url);
    if (!channel.extensions.includes(IDENTITY_EXTENSION)) return { kind: "unsupported" };
  } catch (e) {
    if (e instanceof IdentityUnavailable)
      return { kind: "unavailable", operation: "", reason: e.message };
    throw e;
  } finally {
    pool.closeAll();
  }
  for (;;) {
    const id = await prepare(options, journal);
    if (id !== undefined) return resumeIdentityCreation(options, id);
  }
}

/**
 * Builds Genesis, the epoch-0 DEK and both units and journals them before
 * anything is sent. Undefined when actor sequence 1 was not available for
 * the new Resource (it is then abandoned unhosted).
 */
async function prepare(
  options: CreateIdentityResourceOptions,
  journal: OperationJournal,
): Promise<string | undefined> {
  const P = options.installation.signer;
  const I = generateResourceId();
  const dek = generateResourceDEK();
  const genesis = signControlRecord(
    { resourceId: I, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: IDENTITY_PROFILE,
      owner: P.descriptor,
      dekCommitment: dekCommitment(I, dataEpoch(0n), dek),
      endpoints: [{ url: options.url, priority: 0n }],
      coordinatorUrl: options.url,
    },
    P,
  );
  const chain = validateControlChain([genesis.bytes]);
  if (chain.kind !== "linear") throw new Error("the new Genesis does not validate");
  // The DEK first (LFCP-034), then the chain row that references it.
  await storeDek(options.storage, options.secrets, chain, dataEpoch(0n), dek);
  const doc = options.document(I, P.descriptor.principalId);
  const unit = async (
    seq: bigint,
    intents: readonly IdentityIntent[],
    previous: Uint8Array | null,
  ) => {
    const created = await createDataUnit({
      view: chain,
      controlHead: chain.state.head,
      actor: P,
      dek,
      sequences: options.storage.actorSequences,
      previousUnitId: previous as never,
      profile: identityPlaintextCodec,
      value: doc.write(
        { signer: P.descriptor.principalId, actorSeq: seq, writerClass: "root" },
        intents,
      ),
    });
    return created.seq === seq ? created : undefined;
  };
  const initial = await unit(1n, [{ intent: "identity.initialize" }], null);
  if (initial === undefined) return undefined;
  const fill = await unit(
    2n,
    [
      ...options.roster.map(
        (r) =>
          ({
            intent: "roster.put",
            key: resourceRef(r.resource),
            entry: r.entry,
          }) as IdentityIntent,
      ),
      {
        intent: "device.put",
        key: principalRefOf(P.descriptor.principalId),
        entry: {
          label: options.label,
          kind: 0,
          ...(options.platform === undefined ? {} : { platform: options.platform }),
          ...(options.addedAt === undefined ? {} : { added_at: options.addedAt }),
        },
      },
    ],
    initial.unitId,
  );
  if (fill === undefined) return undefined;
  const id = newOperationId("create-identity", secureRandom(8));
  const R = toHex(I);
  await journal.begin({
    id,
    kind: "create-identity",
    createdAt: options.now(),
    intent: { identity: R, url: options.url, label: options.label },
    phases: [
      { id: "host", kind: "host", resource: R, state: "pending", bytes: toHex(genesis.bytes) },
      { id: "unit:1", kind: "unit", resource: R, state: "pending", bytes: toHex(initial.bytes) },
      { id: "unit:2", kind: "unit", resource: R, state: "pending", bytes: toHex(fill.bytes) },
    ],
  });
  return id;
}

/** Sends what an open creation has not sent yet, from its journaled exact bytes. */
export async function resumeIdentityCreation(
  options: Omit<CreateIdentityResourceOptions, "roster" | "label">,
  operation: string,
): Promise<CreatedIdentityResource> {
  const journal = new OperationJournal(options.storage);
  let op: JournalOperation = await journal.load(operation);
  const I = resourceId(fromHex(op.intent.identity as string));
  const pool = new ChannelPool(options.network);
  try {
    const channel = await pool.get(options.installation.signer, op.intent.url as string);
    const host = phaseOf(op, "host") as JournalPhase;
    if (host.state !== "committed-own") {
      const answer = await channel.host(fromHex(host.bytes as string));
      // W §39: the Genesis a server already hosts is answered with RESOURCE_HOSTED again.
      if (answer.kind === "nack") {
        await journal.putPhase(operation, { ...host, state: "refused", code: answer.code });
        await journal.setStatus(operation, "abandoned");
        return { kind: "refused", code: answer.code };
      }
      op = await journal.putPhase(operation, { ...host, state: "committed-own" });
    }
    for (const id of ["unit:1", "unit:2"]) {
      const r = await runUnitPhase(channel, journal, operation, {
        id,
        resource: I,
        build: () => Promise.reject(new Error("the unit is journaled")),
      });
      if (r.state === "refused") {
        await journal.setStatus(operation, "abandoned");
        return { kind: "refused", code: r.code ?? "refused" };
      }
    }
    const chain = await syncChain(options.storage, channel, I);
    await setLocalIdentityResource(options.storage, I);
    await journal.setStatus(operation, "done");
    const document = options.document(I, chain.state.owner.principalId);
    // The document as the coordinator holds it (the local port of a resumed run is fresh).
    await loadIdentityDocument({
      channel,
      chain,
      deks: await heldDeks(options.secrets, chain),
      doc: document,
    });
    return { kind: "created", identity: I, chain, document, operation };
  } catch (e) {
    if (e instanceof IdentityUnavailable)
      return { kind: "unavailable", operation, reason: e.message };
    throw e;
  } finally {
    pool.closeAll();
  }
}
