/**
 * Durable Node.js storage for LFCP clients (LFCP-035): LfcpStorage on
 * SQLite and a file SecretStore. Node only: for headless Node, the CLI,
 * examples and tests. Obsidian uses its own adapter (LFCP-059), which runs
 * the same contract suite. Also the headless `lfcp-node pair` command of a
 * service device (IDENTITY-PROFILE-01 §5.3, LFCP-04-412).
 */
export const PACKAGE = "@openlfcp/storage-node";

export { identityDocument } from "./identity-document.js";
export { openInstallation } from "./installation.js";
export {
  main,
  PAIR_EXIT,
  PAIR_USAGE,
  type PairArguments,
  type PairEnvironment,
  pair,
  parsePairArguments,
} from "./pair.js";
export { MIGRATIONS, migrate, SCHEMA_VERSION, schemaVersion } from "./schema.js";
export { FileSecretStore } from "./secrets.js";
export {
  SqliteLfcpStorage,
  type SqliteLocalState,
  type SqliteStorageOptions,
} from "./sqlite.js";
