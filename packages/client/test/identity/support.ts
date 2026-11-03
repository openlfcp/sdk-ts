import { principalId } from "@openlfcp/core";
import { importAgreementKey, importSigningKey } from "@openlfcp/crypto";
import { InMemoryLfcpStorage, InMemorySecretStore } from "@openlfcp/storage";
import { principalDescriptorFromKeys, type Signer } from "@openlfcp/wire";
import type { Installation } from "../../src/identity/context.js";

export const fill = (n: number, length = 32) => new Uint8Array(length).fill(n);

const cache = new Map<number, Installation>();
/** Party n: Ed25519 seed [n; 32], X25519 key [n + 100; 32] (as the wire tests). */
export function party(n: number): Installation {
  let p = cache.get(n);
  if (p === undefined) {
    const key = importSigningKey(fill(n));
    const agreement = importAgreementKey(fill(n + 100));
    const signer: Signer = { key, descriptor: principalDescriptorFromKeys(key, agreement) };
    p = { signer, agreement };
    cache.set(n, p);
  }
  return p;
}
export const pid = (n: number) => principalId(party(n).signer.descriptor.principalId);

/** One installation's local state: storage and secrets survive a "restart"; ports do not. */
export function device() {
  return { storage: new InMemoryLfcpStorage(), secrets: new InMemorySecretStore() };
}

export const URL = "wss://identity.example.test/v1/ws";
