import { type DataEpoch, dataEpoch, type ResourceId, toHex } from "@openlfcp/core";
import { importResourceDEK, type ResourceDEK } from "@openlfcp/crypto";
import { dekSecretRef, type LfcpStorage, type SecretStore } from "@openlfcp/storage";

/**
 * The journal of a capability claim in flight (LFCP-02-110).
 *
 * A one-time invitation is spent when the coordinator commits the claim
 * (LFCP-WIRE-01 §18.1). If the CONTROL_PUT's answer is lost, the claimant
 * cannot tell whether it was: retrying with the link fails once the
 * invitation is used up, and the claimant would be left without the chain
 * and the DEK. So before every claim is sent, the claimant journals it:
 * the claim record, the head it expects, the validated chain up to that
 * head, and the epochs whose DEKs it holds (the DEKs themselves go to the
 * SecretStore first, LFCP-034). After a lost answer, the same record is
 * sent again: a coordinator answers a record it has already committed with
 * the same ACK (§47, §70), so a claim that landed completes without
 * spending the invitation twice, and one that did not is refused or meets
 * a moved head.
 *
 * The journal is a local mark (`invitation-claim:<resource hex>`). It holds
 * no secret: the claim and the chain are signed public records.
 */

/** A journaled claim, as JSON in a local mark. Byte strings are hex. */
export interface ClaimJournal {
  readonly v: 1;
  readonly resourceId: string;
  /** The invitation grant the claim spends. */
  readonly invitationGrantId: string;
  /** The claimant's Principal ID. */
  readonly claimant: string;
  /** The signed CAPABILITY_CLAIM record. */
  readonly claim: string;
  /** The head the claim was sent against (its prev_control_id). */
  readonly expectedHead: string;
  /** The validated Control Records up to that head, in order. */
  readonly chain: readonly string[];
  /** The epochs whose DEK is in the SecretStore, as decimal strings. */
  readonly epochs: readonly string[];
  /** The claimed abilities, as decimal strings. */
  readonly abilities: readonly string[];
}

const PREFIX = "invitation-claim:";
const key = (resource: ResourceId): string => `${PREFIX}${toHex(resource)}`;

type JournalStorage = Pick<LfcpStorage, "localMarks" | "commit">;

/** Writes the DEKs to the SecretStore, then the journal (secret first, LFCP-034). */
export async function writeClaimJournal(
  storage: JournalStorage,
  secrets: SecretStore,
  resource: ResourceId,
  journal: ClaimJournal,
  deks: ReadonlyMap<string, ResourceDEK>,
  exportDek: (dek: ResourceDEK) => Uint8Array,
): Promise<void> {
  for (const [epoch, dek] of deks) {
    const bytes = exportDek(dek);
    try {
      await secrets.put(dekSecretRef(resource, dataEpoch(BigInt(epoch))), bytes);
    } finally {
      bytes.fill(0);
    }
  }
  const result = await storage.commit([
    { op: "put-local-mark", key: key(resource), value: JSON.stringify(journal) },
  ]);
  if (!result.ok) throw new Error(`the claim journal was not stored: ${result.reason}`);
}

/** The journaled claim of `resource`, if any. */
export async function readClaimJournal(
  storage: Pick<LfcpStorage, "localMarks">,
  resource: ResourceId,
): Promise<ClaimJournal | undefined> {
  const value = await storage.localMarks.get(key(resource));
  return value === undefined ? undefined : (JSON.parse(value) as ClaimJournal);
}

/** Removes the journal of `resource` once its claim's outcome is known. */
export async function clearClaimJournal(
  storage: JournalStorage,
  resource: ResourceId,
): Promise<void> {
  await storage.commit([{ op: "put-local-mark", key: key(resource), value: null }]);
}

/** Every journaled claim, e.g. to resume them after a restart (resumeInvitationClaim). */
export async function pendingInvitationClaims(
  storage: Pick<LfcpStorage, "localMarks">,
): Promise<readonly ClaimJournal[]> {
  return (await storage.localMarks.list(PREFIX)).map((m) => JSON.parse(m.value) as ClaimJournal);
}

/** The journaled epochs' DEKs, from the SecretStore. */
export async function journaledDeks(
  secrets: SecretStore,
  resource: ResourceId,
  journal: ClaimJournal,
): Promise<Map<string, ResourceDEK>> {
  const deks = new Map<string, ResourceDEK>();
  for (const epoch of journal.epochs) {
    const bytes = await secrets.get(dekSecretRef(resource, dataEpoch(BigInt(epoch)) as DataEpoch));
    if (bytes === undefined) continue;
    try {
      deks.set(epoch, importResourceDEK(bytes));
    } finally {
      bytes.fill(0);
    }
  }
  return deks;
}
