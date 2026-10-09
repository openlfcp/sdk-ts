/**
 * Durable Node.js storage for LFCP clients (LFCP-035): LfcpStorage on
 * SQLite and a file SecretStore. Node only: for headless Node, the CLI,
 * examples and tests. Obsidian uses its own adapter (LFCP-059), which runs
 * the same contract suite.
 */
export const PACKAGE = "@openlfcp/storage-node";

export { MIGRATIONS, migrate, SCHEMA_VERSION, schemaVersion } from "./schema.js";
export { FileSecretStore } from "./secrets.js";
export {
  SqliteLfcpStorage,
  type SqliteLocalState,
  type SqliteStorageOptions,
} from "./sqlite.js";
