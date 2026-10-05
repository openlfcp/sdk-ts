/// <reference types="node" />
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileSecretStore, SqliteLfcpStorage } from "../src/index.js";

/**
 * An isolated store in a fresh temporary directory (never a real LFCP data
 * directory). dispose() closes it and deletes the directory.
 */
export function tempStore(): {
  readonly dir: string;
  readonly dbPath: string;
  readonly secretsDir: string;
  storage: SqliteLfcpStorage;
  secrets: FileSecretStore;
  reopen(): { storage: SqliteLfcpStorage; secrets: FileSecretStore };
  dispose(): void;
} {
  const dir = mkdtempSync(join(tmpdir(), "lfcp-storage-node-"));
  const dbPath = join(dir, "lfcp.sqlite");
  const secretsDir = join(dir, "secrets");
  const store = {
    dir,
    dbPath,
    secretsDir,
    storage: SqliteLfcpStorage.open(dbPath),
    secrets: new FileSecretStore(secretsDir),
    reopen() {
      store.storage.close();
      store.storage = SqliteLfcpStorage.open(dbPath);
      store.secrets = new FileSecretStore(secretsDir);
      return { storage: store.storage, secrets: store.secrets };
    },
    dispose() {
      store.storage.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return store;
}
