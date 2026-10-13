import type { ResourceId } from "@openlfcp/core";
import { dekSecretRef, type SecretRef, type SecretStore } from "./secrets.js";
import type { CommitResult, LfcpStorage } from "./store.js";

/**
 * Forgets a Resource this client made and never sent (a share given up
 * before it was hosted): every stored row of it in one atomic commit
 * (delete-resource), then the secrets only it used, its Data Epoch keys.
 * The local Principal's keys are kept: other Resources use them. Refused,
 * with nothing deleted, when the Resource may have been sent
 * (RESOURCE_SENT). The rows go first: a crash before the keys are deleted
 * leaves keys nothing refers to, never a Resource without its keys.
 */
export async function deleteUnsentResource(
  storage: LfcpStorage,
  secrets: SecretStore,
  resource: ResourceId,
): Promise<CommitResult> {
  const epochs = await storage.control.epochs(resource);
  const refs = new Set<SecretRef>(epochs.map((e) => e.dekRef ?? dekSecretRef(resource, e.epoch)));
  const result = await storage.commit([{ op: "delete-resource", resourceId: resource }]);
  if (!result.ok) return result;
  for (const ref of refs) await secrets.delete(ref);
  return result;
}
