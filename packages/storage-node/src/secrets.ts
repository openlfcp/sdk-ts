import {
  chmodSync,
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { LfcpError } from "@openlfcp/core";
import { isSecretRef, type SecretRef, type SecretStore } from "@openlfcp/storage";

/**
 * A SecretStore in a local directory (LFCP-035), for headless Node, the
 * CLI, examples and tests.
 *
 * MVP LIMITATION: secrets are stored IN PLAINTEXT, protected only by file
 * permissions: the directory is 0700 and every file 0600, owned by the
 * running user. Anyone who can read the files as that user (or as root, or
 * from a backup) has the keys. OS keychain integration or passphrase
 * encryption is a follow-up.
 *
 * One file per SecretRef, named by the hex of the reference (references
 * are public names, never secret material). A write goes to a temporary
 * file that is fsynced, renamed over the target and followed by an fsync
 * of the directory, so a crash leaves the old value or the new one, never
 * a torn file. There is no list operation, and the store renders as
 * "[FileSecretStore]" so values cannot leak into logs.
 */

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

const fileName = (ref: SecretRef): string => `${Buffer.from(ref, "utf8").toString("hex")}.secret`;

export class FileSecretStore implements SecretStore {
  readonly #dir: string;
  #counter = 0;

  /** Creates the directory (0700) if needed and tightens its mode. */
  constructor(dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
    if (!statSync(dir).isDirectory())
      throw new LfcpError("UNSUPPORTED_VALUE", "the secret store location is not a directory");
    this.#dir = dir;
  }

  #check(ref: SecretRef): void {
    if (!isSecretRef(ref)) throw new LfcpError("UNSUPPORTED_VALUE", "not a secret reference");
  }

  #syncDir(): void {
    const fd = openSync(this.#dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  put(ref: SecretRef, value: Uint8Array): Promise<void> {
    try {
      this.#check(ref);
      const target = join(this.#dir, fileName(ref));
      this.#counter += 1;
      const temp = join(this.#dir, `.tmp-${process.pid}-${this.#counter}-${fileName(ref)}`);
      const fd = openSync(temp, "wx", 0o600);
      try {
        writeSync(fd, value);
        fsyncSync(fd);
      } catch (e) {
        closeSync(fd);
        rmSync(temp, { force: true });
        throw e;
      }
      closeSync(fd);
      renameSync(temp, target);
      this.#syncDir();
      return Promise.resolve();
    } catch (e) {
      return Promise.reject(e);
    }
  }

  get(ref: SecretRef): Promise<Uint8Array | undefined> {
    try {
      this.#check(ref);
      return Promise.resolve(Uint8Array.from(readFileSync(join(this.#dir, fileName(ref)))));
    } catch (e) {
      if ((e as { code?: unknown }).code === "ENOENT") return Promise.resolve(undefined);
      return Promise.reject(e);
    }
  }

  delete(ref: SecretRef): Promise<void> {
    try {
      this.#check(ref);
      unlinkSync(join(this.#dir, fileName(ref)));
      this.#syncDir();
    } catch (e) {
      if ((e as { code?: unknown }).code !== "ENOENT") return Promise.reject(e);
    }
    return Promise.resolve();
  }

  toJSON(): string {
    return "[FileSecretStore]";
  }

  toString(): string {
    return "[FileSecretStore]";
  }

  [INSPECT](): string {
    return "[FileSecretStore]";
  }
}
