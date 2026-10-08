import {
  type DataEpoch,
  dataEpoch,
  LfcpError,
  type PrincipalId,
  type ResourceId,
  toHex,
} from "@openlfcp/core";

/**
 * Client secret material (LFCP-034): Principal private keys, Resource DEKs,
 * invitation secrets and local state keys (LFCP-02-098) live only in a
 * SecretStore. Public storage rows
 * hold a SecretRef, a name that reveals nothing about the value.
 *
 * A SecretStore cannot be enumerated: there is no list operation, so no
 * caller can dump its contents into a log or a diagnostic. Backends are
 * platform specific: app.secretStorage in Obsidian (LFCP-059), a file
 * keystore in Node (LFCP-035). No cloud KMS is required.
 *
 * Ordering rule, since a SecretStore is usually a different backend from
 * the public rows and cannot join their atomic batch: write the secret
 * first, then commit the row that references it. A reference without a
 * value is a recoverable gap; a value without a reference is harmless.
 */

export type SecretKind =
  | "principal-signing-key"
  | "principal-agreement-key"
  | "resource-dek"
  | "invitation-secret"
  | "local-state-key";

/** The name of a secret: "lfcp-secret:<kind>:<id>". It never contains secret material. */
export type SecretRef = string & { readonly __secretRef: true };

const KINDS = new Set<string>([
  "principal-signing-key",
  "principal-agreement-key",
  "resource-dek",
  "invitation-secret",
  "local-state-key",
]);
const ID = /^[A-Za-z0-9._-]{1,200}$/;

/** A secret reference; `id` is a public name such as hex IDs joined with ".". */
export function secretRef(kind: SecretKind, id: string): SecretRef {
  if (!KINDS.has(kind)) throw new LfcpError("UNSUPPORTED_VALUE", `unknown secret kind ${kind}`);
  if (!ID.test(id))
    throw new LfcpError("UNSUPPORTED_VALUE", "a secret reference id is [A-Za-z0-9._-]{1,200}");
  return `lfcp-secret:${kind}:${id}` as SecretRef;
}

/** True when `text` is a well-formed secret reference. */
export function isSecretRef(text: unknown): text is SecretRef {
  if (typeof text !== "string") return false;
  const m = /^lfcp-secret:([a-z-]+):(.+)$/.exec(text);
  return m !== null && KINDS.has(m[1] as string) && ID.test(m[2] as string);
}

/** The reference of the DEK of `epoch` of `resource`. */
export const dekSecretRef = (resource: ResourceId, epoch: DataEpoch): SecretRef =>
  secretRef("resource-dek", `${toHex(resource)}.${dataEpoch(epoch)}`);

/** The reference of a local Principal's private signing or agreement key. */
export const principalKeySecretRef = (
  principal: PrincipalId,
  which: "signing" | "agreement",
): SecretRef =>
  secretRef(
    which === "signing" ? "principal-signing-key" : "principal-agreement-key",
    toHex(principal),
  );

export interface SecretStore {
  /** Stores a copy of `value` under `ref`, replacing any previous value. Durable before it resolves. */
  put(ref: SecretRef, value: Uint8Array): Promise<void>;
  /** A copy of the value, or undefined. */
  get(ref: SecretRef): Promise<Uint8Array | undefined>;
  delete(ref: SecretRef): Promise<void>;
}

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/**
 * FOR TESTS AND DEVELOPMENT ONLY: secrets in plain process memory, lost on
 * restart. Renders as "[InMemorySecretStore]" in JSON and inspection, so it
 * cannot leak values into logs by accident.
 */
export class InMemorySecretStore implements SecretStore {
  readonly #values = new Map<string, Uint8Array>();

  put(ref: SecretRef, value: Uint8Array): Promise<void> {
    if (!isSecretRef(ref))
      return Promise.reject(new LfcpError("UNSUPPORTED_VALUE", "not a secret reference"));
    this.#values.set(ref, Uint8Array.from(value));
    return Promise.resolve();
  }

  get(ref: SecretRef): Promise<Uint8Array | undefined> {
    const v = this.#values.get(ref);
    return Promise.resolve(v === undefined ? undefined : Uint8Array.from(v));
  }

  delete(ref: SecretRef): Promise<void> {
    this.#values.delete(ref);
    return Promise.resolve();
  }

  toJSON(): string {
    return "[InMemorySecretStore]";
  }

  toString(): string {
    return "[InMemorySecretStore]";
  }

  [INSPECT](): string {
    return "[InMemorySecretStore]";
  }
}
