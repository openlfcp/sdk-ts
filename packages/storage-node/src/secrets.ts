import { createHash } from "node:crypto";
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
 * One file per SecretRef, named by the SHA-256 of the reference, in hex
 * (references are public names, never secret material): 71 ASCII
 * characters for any reference, within every file system's name limit and
 * valid on Windows. Before 0.5.3 a file was named by the hex of the whole
 * reference, which a reference longer than 124 characters could not be
 * (ENAMETOOLONG); a file under that legacy name is still read, and moved to
 * its new name when it is read or written (legacyFileName). A write goes to a temporary
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

/** The file of a reference: the SHA-256 of its UTF-8 bytes, hex, and `.secret`. */
export const secretFileName = (ref: SecretRef): string =>
  `${createHash("sha256").update(ref, "utf8").digest("hex")}.secret`;

/** The longest file name every supported file system takes (NAME_MAX on ext4, APFS, NTFS). */
const NAME_MAX = 255;

/**
 * The file name before 0.5.3: the hex of the reference. undefined when
 * that name is too long to exist (such a reference could never be stored).
 */
export function legacyFileName(ref: SecretRef): string | undefined {
  const name = `${Buffer.from(ref, "utf8").toString("hex")}.secret`;
  return name.length <= NAME_MAX ? name : undefined;
}

const code = (e: unknown): unknown => (e as { code?: unknown }).code;

function readIfExists(path: string): Uint8Array | undefined {
  try {
    return Uint8Array.from(readFileSync(path));
  } catch (e) {
    if (code(e) === "ENOENT") return undefined;
    throw e;
  }
}

function unlinkIfExists(path: string): boolean {
  try {
    unlinkSync(path);
    return true;
  } catch (e) {
    if (code(e) === "ENOENT") return false;
    throw e;
  }
}

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

  /** Writes `value` under the reference's file: a fsynced temporary file renamed over it. */
  #write(ref: SecretRef, value: Uint8Array): void {
    const name = secretFileName(ref);
    this.#counter += 1;
    const temp = join(this.#dir, `.tmp-${process.pid}-${this.#counter}-${name}`);
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
    renameSync(temp, join(this.#dir, name));
    this.#syncDir();
  }

  /**
   * Removes the legacy file of `ref` once its value is durable under the new
   * name: a crash in between leaves both, and the new one is read first.
   */
  #dropLegacy(ref: SecretRef): void {
    const legacy = legacyFileName(ref);
    if (legacy !== undefined && unlinkIfExists(join(this.#dir, legacy))) this.#syncDir();
  }

  put(ref: SecretRef, value: Uint8Array): Promise<void> {
    try {
      this.#check(ref);
      this.#write(ref, value);
      this.#dropLegacy(ref);
      return Promise.resolve();
    } catch (e) {
      return Promise.reject(e);
    }
  }

  get(ref: SecretRef): Promise<Uint8Array | undefined> {
    try {
      this.#check(ref);
      const current = readIfExists(join(this.#dir, secretFileName(ref)));
      if (current !== undefined) return Promise.resolve(current);
      const legacy = legacyFileName(ref);
      if (legacy === undefined) return Promise.resolve(undefined);
      const old = readIfExists(join(this.#dir, legacy));
      if (old === undefined) return Promise.resolve(undefined);
      // A file of 0.5.2 or earlier: moved to its new name, then the old one goes.
      this.#write(ref, old);
      this.#dropLegacy(ref);
      return Promise.resolve(old);
    } catch (e) {
      return Promise.reject(e);
    }
  }

  delete(ref: SecretRef): Promise<void> {
    try {
      this.#check(ref);
      // The legacy file first: a crash after it leaves the current value, never an older one.
      const legacy = legacyFileName(ref);
      let removed = legacy !== undefined && unlinkIfExists(join(this.#dir, legacy));
      removed = unlinkIfExists(join(this.#dir, secretFileName(ref))) || removed;
      if (removed) this.#syncDir();
      return Promise.resolve();
    } catch (e) {
      return Promise.reject(e);
    }
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
