// The installation's own Principal for a headless client (LFCP-04-412): its
// Ed25519 and X25519 keys in the SecretStore (principalKeySecretRef), its
// public Principal ID in <state>/installation.json. Created once, on the
// first run; a copied state directory is a misconfiguration (a Principal
// has exactly one writing installation, W §7.1).

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Installation } from "@openlfcp/client";
import { fromHex, principalId, toHex } from "@openlfcp/core";
import {
  exportSecretKeyBytes,
  generateAgreementKeyPair,
  generateSigningKeyPair,
  importAgreementKey,
  importSigningKey,
} from "@openlfcp/crypto";
import { principalKeySecretRef, type SecretStore } from "@openlfcp/storage";
import { principalDescriptorFromKeys } from "@openlfcp/wire";

const FILE = "installation.json";

/** This state directory's installation, created on first use. */
export async function openInstallation(dir: string, secrets: SecretStore): Promise<Installation> {
  const path = join(dir, FILE);
  if (existsSync(path)) {
    const { principal } = JSON.parse(readFileSync(path, "utf8")) as { principal: string };
    const id = principalId(fromHex(principal));
    const seed = await secrets.get(principalKeySecretRef(id, "signing"));
    const scalar = await secrets.get(principalKeySecretRef(id, "agreement"));
    if (seed === undefined || scalar === undefined)
      throw new Error(`the keys of installation ${principal} are missing`);
    try {
      const key = importSigningKey(seed);
      const agreement = importAgreementKey(scalar);
      const descriptor = principalDescriptorFromKeys(key, agreement);
      if (toHex(descriptor.principalId) !== principal)
        throw new Error(`the keys do not derive installation ${principal}`);
      return { signer: { key, descriptor }, agreement };
    } finally {
      seed.fill(0);
      scalar.fill(0);
    }
  }
  const key = generateSigningKeyPair();
  const agreement = generateAgreementKeyPair();
  const descriptor = principalDescriptorFromKeys(key, agreement);
  const id = descriptor.principalId;
  for (const [which, k] of [
    ["signing", key],
    ["agreement", agreement],
  ] as const) {
    const bytes = exportSecretKeyBytes(k);
    try {
      await secrets.put(principalKeySecretRef(id, which), bytes);
    } finally {
      bytes.fill(0);
    }
  }
  // The keys are durable before the ID names them.
  writeFileSync(`${path}.tmp`, `${JSON.stringify({ principal: toHex(id) })}\n`, { mode: 0o600 });
  renameSync(`${path}.tmp`, path);
  return { signer: { key, descriptor }, agreement };
}
