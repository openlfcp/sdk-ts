/// <reference lib="dom" />
import "fake-indexeddb/auto";
import { InMemorySecretStore } from "@openlfcp/storage";
import { runStorageContract } from "@openlfcp/storage/contract";
import { describe, it } from "vitest";
import { IdbLfcpStorage } from "../src/index.js";
import { standInCipher } from "./stand-in-cipher.js";

// The shared LfcpStorage contract (LFCP-034) on IndexedDB (fake-indexeddb
// in Node), each test in its own database. Secrets are not this package's
// concern; the in-memory store stands in.
let n = 0;
runStorageContract({ describe, it }, "IdbLfcpStorage", async () => {
  const name = `contract-${++n}`;
  let storage = await IdbLfcpStorage.open(name);
  const secrets = new InMemorySecretStore();
  const handle = {
    get storage() {
      return storage;
    },
    secrets,
    reopen: async () => {
      storage.close();
      storage = await IdbLfcpStorage.open(name);
      return handle;
    },
    close: async () => {
      storage.close();
      indexedDB.deleteDatabase(name);
    },
  };
  return handle;
});

// The same contract with the local state sealed at rest (LFCP-02-098).
runStorageContract({ describe, it }, "IdbLfcpStorage with localState", async () => {
  const name = `contract-sealed-${++n}`;
  const secrets = new InMemorySecretStore();
  const options = { localState: { secrets, cipher: standInCipher } };
  let storage = await IdbLfcpStorage.open(name, options);
  const handle = {
    get storage() {
      return storage;
    },
    secrets,
    reopen: async () => {
      storage.close();
      storage = await IdbLfcpStorage.open(name, options);
      return handle;
    },
    close: async () => {
      storage.close();
      indexedDB.deleteDatabase(name);
    },
  };
  return handle;
});
