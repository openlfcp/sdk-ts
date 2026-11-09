// What a paired installation knows about itself, offline (504, spike B-001
// gaps G1 and G4): the Resources its pairing brought and the device it is.
// A headless device (a bridge or a bot, IDENTITY-PROFILE-01 §10) cannot read
// the person's roster or device list; everything here comes from its own
// storage: the pairing journal (§5.3, §9.1), the stored Control Chains and
// the Data Epoch keys.

import {
  bytesEqual,
  fromHex,
  hash32,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { type LfcpStorage, principalKeySecretRef, type SecretStore } from "@openlfcp/storage";
import {
  certificateChain,
  DEVICE_KIND,
  type DeviceKind,
  parseDeviceCertificate,
} from "@openlfcp/wire";
import { loadControlChain, writeBarrier } from "../storage.js";
import { genesisOwner, type IdentityStorage, type Installation } from "./context.js";
import { type JournalOperation, OperationJournal } from "./journal.js";
import { candidateEvidence } from "./pairing-request.js";
import { localIdentityResource } from "./resource.js";

/** A Resource a pairing brought to this installation (a candidate of its request, §5.3). */
export interface PairedResource {
  readonly resource: ResourceId;
  /** Its roster name when the request was made. */
  readonly name?: string;
  /** Its Data Profile, from the roster entry. */
  readonly profile: string;
  /** Its coordinator. */
  readonly url: string;
  /**
   * Usable here, as completePairing's "ready": in the approved scope; this
   * device proven by the approval and registered with its approved kind,
   * mask and scope; its revocation not proven here (revocationStatus); the
   * key of every Data Epoch in the SecretStore. A candidate left out of the
   * scope, still pending, or revoked is not ready.
   */
  readonly ready: boolean;
}

/** What reading the journal and the chains needs: any identity flow's storage. */
type Storage = IdentityStorage;

interface CandidateJson {
  readonly resource: string;
  readonly url: string;
  readonly profile: string;
  readonly name?: string;
}

/** The pairing request of this installation that got a certificate, the latest one. */
async function approvedRequest(storage: Storage): Promise<JournalOperation | undefined> {
  const ops = await new OperationJournal(storage).list({ kind: "pairing-request" });
  return ops
    .filter((o) => o.intent.result === "approved" && o.intent.certificate !== undefined)
    .sort((a, b) => a.createdAt - b.createdAt)
    .at(-1);
}

/** The approved certificate's payload and approval digest, from the journal. */
function approval(op: JournalOperation) {
  const root = principalId(fromHex(op.intent.root as string));
  const result = certificateChain(
    (op.intent.certificate as string[]).map((c) => parseDeviceCertificate(fromHex(c))),
    root,
  ).leaf.payload;
  return {
    device: principalId(fromHex(op.intent.device as string)),
    digest: hash32(fromHex(op.intent.digest as string)),
    result,
  };
}

/**
 * Usable here, by the rules completePairing reports "ready" with (§5.3
 * step 8): in the approved scope; the device proven by the approval and
 * registered with exactly the approved kind, mask and scope
 * (candidateEvidence); its revocation not proven here (the write barrier
 * revocationStatus records, which the device's own chain may never show);
 * and the key of every epoch of the stored chain in the SecretStore, not
 * only referenced.
 */
async function isReady(
  o: { readonly storage: Storage; readonly secrets: SecretStore },
  a: ReturnType<typeof approval>,
  resource: ResourceId,
): Promise<boolean> {
  if (
    a.result.kind !== DEVICE_KIND.PERSONAL &&
    !a.result.scope.some((r) => bytesEqual(r, resource))
  )
    return false;
  const chain = await loadControlChain(o.storage, resource);
  if (chain?.kind !== "linear") return false;
  if (!candidateEvidence(chain, a.device, a.digest, a.result).usable) return false;
  if ((await writeBarrier(o.storage, resource))?.state === "revocation-proven") return false;
  const rows = new Map((await o.storage.control.epochs(resource)).map((e) => [String(e.epoch), e]));
  if (chain.state.epochs.size === 0) return false;
  for (const epoch of chain.state.epochs.keys()) {
    const ref = rows.get(epoch)?.dekRef;
    if (ref === null || ref === undefined) return false;
    const key = await o.secrets.get(ref);
    if (key === undefined) return false;
    key.fill(0);
  }
  return true;
}

/**
 * The Resources this installation's pairing brought, in the order of its
 * request, the Identity Resource excluded; empty when it was not paired (a
 * person's first installation) or its approval is not known yet. Works for
 * installations paired by any earlier version: it reads the pairing journal
 * and the stored chains only, never the network.
 */
export async function pairedResources(o: {
  readonly storage: Storage;
  /** Where the Data Epoch keys are: a key is held when it is there, not when a row names it. */
  readonly secrets: SecretStore;
}): Promise<readonly PairedResource[]> {
  const op = await approvedRequest(o.storage);
  if (op === undefined) return [];
  const a = approval(op);
  const out: PairedResource[] = [];
  for (const c of op.intent.candidates as CandidateJson[]) {
    const resource = resourceId(fromHex(c.resource));
    out.push(
      Object.freeze({
        resource,
        ...(c.name === undefined ? {} : { name: c.name }),
        profile: c.profile,
        url: c.url,
        ready: await isReady(o, a, resource),
      }),
    );
  }
  return Object.freeze(out);
}

/**
 * Stores a Resource row (`storage.resources`) for every ready paired
 * Resource that has none, written as this installation's Principal with no
 * labels (a roster name is the person's text: an application keeps it in
 * its own sealed state). Returns the Resources it stored. Idempotent; for
 * installations paired before completePairing could do it (`storeResources`).
 */
export async function storePairedResources(o: {
  readonly storage: Storage & Pick<LfcpStorage, "resources">;
  readonly secrets: SecretStore;
  readonly installation: Installation;
}): Promise<readonly ResourceId[]> {
  const op = await approvedRequest(o.storage);
  // Only the installation that made the request: its rows name its own Principal.
  if (
    op === undefined ||
    !bytesEqual(
      principalId(fromHex(op.intent.device as string)),
      o.installation.signer.descriptor.principalId,
    )
  )
    return [];
  const stored: ResourceId[] = [];
  for (const p of await pairedResources(o)) {
    if (!p.ready || (await o.storage.resources.get(p.resource)) !== undefined) continue;
    await putResourceRow(o.storage, o.installation, p.resource);
    stored.push(p.resource);
  }
  return Object.freeze(stored);
}

/**
 * The Resource row of a Resource whose chain is stored, as `installation`'s
 * Principal. Internal: it checks nothing about the installation's access;
 * its callers (completePairing for a "ready" candidate, storePairedResources)
 * do.
 */
export async function putResourceRow(
  storage: Pick<LfcpStorage, "control" | "commit">,
  installation: Installation,
  resource: ResourceId,
): Promise<void> {
  const chain = await loadControlChain(storage, resource);
  if (chain?.kind !== "linear") throw new Error("the Resource's Control Chain is not stored");
  const id = installation.signer.descriptor.principalId;
  const r = await storage.commit([
    {
      op: "put-resource",
      row: {
        resourceId: resource,
        dataProfile: chain.state.dataProfile,
        localPrincipal: {
          principalId: id,
          signingKeyRef: principalKeySecretRef(id, "signing"),
          agreementKeyRef: principalKeySecretRef(id, "agreement"),
        },
        labels: {},
      },
    },
  ]);
  if (!r.ok) throw new Error(`the Resource row was not stored: ${r.reason}`);
}

/** What this installation is in its person's identity (IDENTITY-PROFILE-01 §§5, 7). */
export type DeviceIdentity =
  /** The person's root itself: the installation that created the Identity Resource. */
  | {
      readonly kind: "root";
      readonly identity: ResourceId;
      readonly root: PrincipalId;
      readonly device: PrincipalId;
      readonly label?: string;
    }
  /** A device paired to the root, with its approved certificate (immutable, N8). */
  | {
      readonly kind: "device";
      readonly identity: ResourceId;
      readonly root: PrincipalId;
      readonly device: PrincipalId;
      /** 0 personal, 1 service. */
      readonly deviceKind: DeviceKind;
      readonly mask: readonly bigint[];
      /** A service device's Resources; empty for a personal device (every roster Resource). */
      readonly scope: readonly ResourceId[];
      /** The label it asked to be added with. */
      readonly label: string;
    };

/**
 * This installation's place in its person's identity, from local state:
 * a paired device's approved certificate (its pairing journal), or the root
 * for the installation that created the Identity Resource. undefined before
 * either: not paired, or the approval not learned yet (completePairing).
 * Whether the device was since revoked is not here: see revocationStatus.
 */
export async function deviceIdentity(o: {
  readonly storage: Storage;
  readonly installation: Installation;
}): Promise<DeviceIdentity | undefined> {
  const me = o.installation.signer.descriptor.principalId;
  const op = await approvedRequest(o.storage);
  if (op !== undefined && bytesEqual(principalId(fromHex(op.intent.device as string)), me)) {
    const root = principalId(fromHex(op.intent.root as string));
    const leaf = certificateChain(
      (op.intent.certificate as string[]).map((c) => parseDeviceCertificate(fromHex(c))),
      root,
    ).leaf.payload;
    return Object.freeze({
      kind: "device",
      identity: resourceId(fromHex(op.intent.identity as string)),
      root,
      device: me,
      deviceKind: leaf.kind,
      mask: Object.freeze([...leaf.mask]),
      scope: Object.freeze([...leaf.scope]),
      label: op.intent.label as string,
    });
  }
  const I = await localIdentityResource(o.storage);
  if (I === undefined) return undefined;
  const chain = await loadControlChain(o.storage, I);
  if (chain?.kind !== "linear" || !bytesEqual(genesisOwner(chain), me)) return undefined;
  const created = (await new OperationJournal(o.storage).list({ kind: "create-identity" })).find(
    (c) => c.intent.identity === toHex(I),
  );
  const label = created?.intent.label;
  return Object.freeze({
    kind: "root",
    identity: I,
    root: me,
    device: me,
    ...(typeof label === "string" ? { label } : {}),
  });
}
