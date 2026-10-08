import { LfcpError, toHex } from "@openlfcp/core";
import { type SecretRef, type SecretStore, secretRef } from "./secrets.js";

/**
 * Local state encrypted at rest (LFCP-02-098; .github
 * docs/devel/design/local-state-encryption.md).
 *
 * A storage adapter opened with a SecretStore seals the rows that hold
 * profile text (ProfileCheckpoint.state) with the install's local state key
 * before they reach the disk, as `lse1` envelopes. The
 * key lives only in the SecretStore, under
 * `lfcp-secret:local-state-key:<install id>.<generation>`; the adapter's
 * metadata records the scheme, the install ID and the current generation,
 * never key bytes.
 *
 * The keyring decides what to do when an adapter opens:
 * - a new install, or a database from before the scheme: create the key
 *   (secret first, then the metadata), then seal every plaintext row
 *   (`migrating`);
 * - a migration or rotation left half done: continue it;
 * - a missing key: never a crash and never a silent deletion. The next
 *   generation's key is created, rows sealed under the lost one read as
 *   unreadable (a checkpoint as absent: the profile state is rebuilt from
 *   the stored units), and they are replaced as they are rewritten.
 * Rotation is explicit: the next generation's key is written, every row is
 * sealed again, then the old key is removed.
 *
 * This package does no cryptography (it may not depend on @openlfcp/crypto,
 * LFCP-014): the application passes the cipher, `localStateCipher` of
 * @openlfcp/crypto, which keeps the key bytes inside that package.
 */

/**
 * The envelope cipher: `localStateCipher` of @openlfcp/crypto
 * (XChaCha20-Poly1305, `lse1` envelopes). Keys are opaque here.
 */
export interface LocalStateCipher<K = unknown> {
  generateKey(): K;
  importKey(bytes: Uint8Array): K;
  /** A copy of the key bytes, for the SecretStore only. */
  exportKey(key: K): Uint8Array;
  seal(key: K, generation: number, aad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  /** Throws on a wrong key, AAD or generation, or tampered bytes. */
  open(key: K, aad: Uint8Array, envelope: Uint8Array): Uint8Array;
  isSealed(bytes: Uint8Array): boolean;
  generationOf(bytes: Uint8Array): number | undefined;
}

/** The scheme an adapter records in its metadata. */
export const LOCAL_STATE_SCHEME = "lse-v1";

/** Something that happened to the local state key, for diagnostics. */
export interface LocalStateEvent {
  readonly kind: "created" | "migrated" | "key-lost" | "rotated";
  /** RFC 3339. */
  readonly at: string;
}

/** The adapter's record of local encryption. It never holds key bytes. */
export interface LocalStateMeta {
  readonly scheme: typeof LOCAL_STATE_SCHEME;
  /** A random public name of this install, in every row's AAD and key reference. */
  readonly installId: string;
  /** The generation rows are sealed with. */
  readonly generation: number;
  /** `ready`, or a migration or rotation to continue on the next open. */
  readonly phase: "migrating" | "rotating" | "ready";
  /** While rotating: the generation being replaced. */
  readonly previous: number | null;
  readonly lastEvent: LocalStateEvent | null;
}

/** A row's bytes as read: plaintext from before the scheme, opened, or unreadable. */
export type OpenedLocal =
  | { readonly kind: "plain"; readonly bytes: Uint8Array }
  | { readonly kind: "opened"; readonly bytes: Uint8Array; readonly generation: number }
  | { readonly kind: "unreadable"; readonly reason: "missing-key" | "authentication" };

/** The SecretStore reference of an install's key of one generation. */
export const localStateKeyRef = (installId: string, generation: number): SecretRef =>
  secretRef("local-state-key", `${installId}.${generation}`);

const LABEL = "openlfcp-local-v1";
// WHATWG TextEncoder and Web Crypto's getRandomValues, which browsers,
// Node.js and editors all provide; declared here so the package needs no DOM
// or Node type library.
const g = globalThis as unknown as {
  TextEncoder: new () => { encode(text: string): Uint8Array };
  crypto: { getRandomValues(bytes: Uint8Array): Uint8Array };
};
const utf8 = (text: string): Uint8Array => new g.TextEncoder().encode(text);

/**
 * The AAD of a row: the label, the install ID, the store and the row's
 * primary key, each length-prefixed, so a row cannot be swapped with
 * another one or moved to another install.
 */
export function localStateAad(installId: string, store: string, key: string): Uint8Array {
  const parts = [utf8(LABEL), utf8(installId), utf8(store), utf8(key)];
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const p of parts) {
    view.setUint32(at, p.length);
    out.set(p, at + 4);
    at += 4 + p.length;
  }
  return out;
}

const randomInstallId = (): string => toHex(g.crypto.getRandomValues(new Uint8Array(16)));

async function loadKey(
  cipher: LocalStateCipher,
  secrets: SecretStore,
  installId: string,
  generation: number,
): Promise<unknown> {
  const bytes = await secrets.get(localStateKeyRef(installId, generation));
  // An empty value marks a deleted secret where the store has no delete.
  if (bytes === undefined || bytes.length === 0) return undefined;
  try {
    return cipher.importKey(bytes);
  } finally {
    bytes.fill(0);
  }
}

async function storeKey(
  cipher: LocalStateCipher,
  secrets: SecretStore,
  installId: string,
  generation: number,
): Promise<unknown> {
  const key = cipher.generateKey();
  const bytes = cipher.exportKey(key);
  try {
    await secrets.put(localStateKeyRef(installId, generation), bytes);
  } finally {
    bytes.fill(0);
  }
  return key;
}

/** An install's local state keys and metadata, held by an open adapter. */
export class LocalStateKeyring {
  readonly #cipher: LocalStateCipher;
  readonly #keys: ReadonlyMap<number, unknown>;
  readonly meta: LocalStateMeta;

  private constructor(
    cipher: LocalStateCipher,
    meta: LocalStateMeta,
    keys: ReadonlyMap<number, unknown>,
  ) {
    this.#cipher = cipher;
    this.meta = Object.freeze({ ...meta });
    this.#keys = keys;
  }

  /**
   * The keyring for an adapter opening with `stored` metadata (undefined: a
   * new install or a database from before the scheme). Writes any new key
   * to `secrets` before it returns; the caller then records `meta` and runs
   * `reseal` while `meta.phase` is not `ready`.
   */
  static async prepare(
    cipher: LocalStateCipher,
    secrets: SecretStore,
    stored: LocalStateMeta | undefined,
    now: string,
  ): Promise<LocalStateKeyring> {
    if (stored === undefined) {
      const installId = randomInstallId();
      const key = await storeKey(cipher, secrets, installId, 1);
      return new LocalStateKeyring(
        cipher,
        {
          scheme: LOCAL_STATE_SCHEME,
          installId,
          generation: 1,
          phase: "migrating",
          previous: null,
          lastEvent: { kind: "created", at: now },
        },
        new Map([[1, key]]),
      );
    }
    if (stored.scheme !== LOCAL_STATE_SCHEME)
      throw new LfcpError("UNSUPPORTED_VALUE", `unknown local state scheme ${stored.scheme}`);
    const keys = new Map<number, unknown>();
    const current = await loadKey(cipher, secrets, stored.installId, stored.generation);
    if (stored.previous !== null) {
      const previous = await loadKey(cipher, secrets, stored.installId, stored.previous);
      if (previous !== undefined) keys.set(stored.previous, previous);
    }
    if (current !== undefined) {
      keys.set(stored.generation, current);
      return new LocalStateKeyring(cipher, stored, keys);
    }
    // The current key is lost: start the next generation. Rows sealed under
    // the lost key stay unreadable until they are rewritten.
    const generation = stored.generation + 1;
    keys.set(generation, await storeKey(cipher, secrets, stored.installId, generation));
    return new LocalStateKeyring(
      cipher,
      {
        ...stored,
        generation,
        phase: stored.phase === "rotating" ? "rotating" : stored.phase,
        lastEvent: { kind: "key-lost", at: now },
      },
      keys,
    );
  }

  /**
   * Begins a rotation: writes the next generation's key to `secrets` and
   * returns the keyring to record (phase `rotating`) before `reseal` runs.
   */
  async rotate(secrets: SecretStore, now: string): Promise<LocalStateKeyring> {
    if (this.meta.phase !== "ready")
      throw new LfcpError("UNSUPPORTED_VALUE", `the local state is ${this.meta.phase}`);
    const generation = this.meta.generation + 1;
    const keys = new Map(this.#keys);
    keys.set(generation, await storeKey(this.#cipher, secrets, this.meta.installId, generation));
    return new LocalStateKeyring(
      this.#cipher,
      {
        ...this.meta,
        generation,
        phase: "rotating",
        previous: this.meta.generation,
        lastEvent: { kind: "rotated", at: now },
      },
      keys,
    );
  }

  /** The keyring once `reseal` has finished: phase `ready`. */
  finished(now: string): LocalStateKeyring {
    const migrated = this.meta.phase === "migrating";
    const keys = new Map([...this.#keys].filter(([g]) => g === this.meta.generation));
    return new LocalStateKeyring(
      this.#cipher,
      {
        ...this.meta,
        phase: "ready",
        previous: null,
        lastEvent: migrated ? { kind: "migrated", at: now } : this.meta.lastEvent,
      },
      keys,
    );
  }

  /** Whether the current generation's key is held. */
  get keyPresent(): boolean {
    return this.#keys.has(this.meta.generation);
  }

  /** The envelope of a row's `plaintext`, under the current key. */
  seal(store: string, key: string, plaintext: Uint8Array): Uint8Array {
    const k = this.#keys.get(this.meta.generation);
    if (k === undefined) throw new LfcpError("CRYPTO_FAILURE", "the local state key is missing");
    return this.#cipher.seal(
      k,
      this.meta.generation,
      localStateAad(this.meta.installId, store, key),
      plaintext,
    );
  }

  /** A row's bytes as stored: plaintext, opened, or unreadable (never a throw). */
  open(store: string, key: string, bytes: Uint8Array): OpenedLocal {
    if (!this.#cipher.isSealed(bytes)) return { kind: "plain", bytes };
    const generation = this.#cipher.generationOf(bytes) as number;
    const k = this.#keys.get(generation);
    if (k === undefined) return { kind: "unreadable", reason: "missing-key" };
    try {
      return {
        kind: "opened",
        bytes: this.#cipher.open(k, localStateAad(this.meta.installId, store, key), bytes),
        generation,
      };
    } catch {
      return { kind: "unreadable", reason: "authentication" };
    }
  }

  /** Whether a stored row needs sealing again: plaintext, or sealed under a readable older generation. */
  needsReseal(bytes: Uint8Array): boolean {
    if (!this.#cipher.isSealed(bytes)) return true;
    const generation = this.#cipher.generationOf(bytes) as number;
    return generation !== this.meta.generation && this.#keys.has(generation);
  }

  /** The SecretStore reference of the key a finished rotation replaced, to remove. */
  get retired(): SecretRef | null {
    return this.meta.previous === null
      ? null
      : localStateKeyRef(this.meta.installId, this.meta.previous);
  }

  toJSON(): string {
    return "[LocalStateKeyring]";
  }
}

/** One row to seal again, as an adapter scans it. */
export interface ResealRow {
  readonly store: string;
  readonly key: string;
  readonly bytes: Uint8Array;
}

/**
 * Seals every row that needs it, in batches: `scan` returns up to `limit`
 * rows after `after` (null: from the start) in key order; `write` stores the
 * sealed rows atomically. Resumable: a row already sealed under the current
 * generation is skipped, so a crash between batches continues on the next
 * open. A row whose key is lost is left as it is.
 */
export async function reseal(
  keyring: LocalStateKeyring,
  scan: (after: string | null, limit: number) => Promise<readonly ResealRow[]>,
  write: (rows: readonly ResealRow[]) => Promise<void>,
  limit = 64,
): Promise<number> {
  let after: string | null = null;
  let count = 0;
  for (;;) {
    const rows = await scan(after, limit);
    if (rows.length === 0) return count;
    const sealed: ResealRow[] = [];
    for (const row of rows) {
      if (!keyring.needsReseal(row.bytes)) continue;
      const opened = keyring.open(row.store, row.key, row.bytes);
      if (opened.kind === "unreadable") continue;
      sealed.push({ ...row, bytes: keyring.seal(row.store, row.key, opened.bytes) });
    }
    if (sealed.length > 0) await write(sealed);
    count += sealed.length;
    after = (rows.at(-1) as ResealRow).key;
    if (rows.length < limit) return count;
  }
}
