/// <reference types="node" />
import { runStorageContract } from "@openlfcp/storage/contract";
import { describe, it } from "vitest";
import { tempStore } from "./fixture.js";

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
