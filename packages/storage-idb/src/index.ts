/**
 * Durable portable storage for LFCP clients (LFCP-059): LfcpStorage on
 * IndexedDB, for browsers, Electron and mobile WebViews. The application
 * names the database (one per client install) and keeps secrets in its own
 * SecretStore.
 */
export const PACKAGE = "@openlfcp/storage-idb";

export {
  IdbLfcpStorage,
  type IdbLocalState,
  type IdbStorageOptions,
  type ReservedSequence,
} from "./idb.js";
