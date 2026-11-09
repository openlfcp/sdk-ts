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
 * a torn file. Windows cannot open a directory for fsync (EPERM, EISDIR or
 * EACCES): there the rename is the last step (syncDirectory). There is no list operation, and the store renders as
 * "[FileSecretStore]" so values cannot leak into logs.
 */

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

/** What syncDirectory needs of node:fs (replaced in tests). */
export interface DirectorySyncOps {
  openSync(path: string, flags: string): number;
  fsyncSync(fd: number): void;
  closeSync(fd: number): void;
}

const FS_OPS: DirectorySyncOps = { openSync, fsyncSync, closeSync };

/** The errors Windows gives for opening or fsyncing a directory. */
const WINDOWS_DIRECTORY_SYNC = new Set(["EPERM", "EISDIR", "EACCES"]);

/**
 * fsyncs `dir`, so that a rename into it is durable (POSIX). On Windows a
 * directory cannot be opened or fsynced (EPERM, EISDIR, EACCES), and NTFS
 * journals the rename itself: those errors are tolerated there, and only
 * there. Every other error, on every platform, is thrown.
 */
export function syncDirectory(
  dir: string,
  platform: NodeJS.Platform = process.platform,
  ops: DirectorySyncOps = FS_OPS,
): void {
  let fd: number;
  try {
    fd = ops.openSync(dir, "r");
  } catch (e) {
    if (platform === "win32" && WINDOWS_DIRECTORY_SYNC.has(String((e as { code?: unknown }).code)))
      return;
    throw e;
  }
  try {
    ops.fsyncSync(fd);
  } catch (e) {
    if (
      !(platform === "win32" && WINDOWS_DIRECTORY_SYNC.has(String((e as { code?: unknown }).code)))
    )
      throw e;
  } finally {
    ops.closeSync(fd);
  }
}

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
    syncDirectory(this.#dir);
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
