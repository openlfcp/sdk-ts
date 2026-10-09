/// <reference types="node" />
import { runStorageContract } from "@openlfcp/storage/contract";
import { describe, it } from "vitest";
import { SqliteLfcpStorage } from "../src/index.js";
import { tempStore } from "./fixture.js";
import { standInCipher } from "./stand-in-cipher.js";

// The shared LfcpStorage and SecretStore contract (LFCP-034) on SQLite and
// the file secret store, each test in its own temporary directory.
runStorageContract({ describe, it }, "SqliteLfcpStorage + FileSecretStore", async () => {
  const t = tempStore();
  return {
    get storage() {
      return t.storage;
    },
    get secrets() {
      return t.secrets;
    },
    reopen: async () => t.reopen(),
    close: async () => t.dispose(),
  };
});

// The same contract with the local state sealed at rest (LFCP-02-098).
runStorageContract({ describe, it }, "SqliteLfcpStorage.openSealed + FileSecretStore", async () => {
  const t = tempStore();
  t.storage.close();
  const open = () =>
    SqliteLfcpStorage.openSealed(t.dbPath, { secrets: t.secrets, cipher: standInCipher });
  let storage = await open();
  return {
    get storage() {
      return storage;
    },
    get secrets() {
      return t.secrets;
    },
    reopen: async () => {
      storage.close();
      storage = await open();
      return { storage, secrets: t.secrets };
    },
    close: async () => {
      storage.close();
      t.dispose();
    },
  };
});
