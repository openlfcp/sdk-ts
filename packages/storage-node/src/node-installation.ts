// A headless installation opened from its state directory (504, spike
// B-001 gap G3): what `lfcp-node pair` assembles, for the bridge or bot
// that runs after it. The directory layout is the command's: lfcp.sqlite,
// secrets/ and installation.json (IDENTITY-PROFILE-01 §5.3 "Headless
// installation"). One directory is one installation: never copy it.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  connectionNetwork,
  type IdentityFlowOptions,
  type IdentityNetwork,
  type Installation,
  type UnitProfile,
} from "@openlfcp/client";
import { sharedObjectsUnitProfile } from "@openlfcp/shared-objects";
import { identityUnitProfile } from "@openlfcp/shared-objects/identity";
import { sectionsUnitProfile } from "@openlfcp/shared-objects/sections";
import { identityDocument } from "./identity-document.js";
import { openInstallation } from "./installation.js";
import { FileSecretStore } from "./secrets.js";
import { SqliteLfcpStorage } from "./sqlite.js";

/** The Data Profiles of this SDK, each as an identity flow checks one unit (FlowOptions.profiles). */
export const NODE_UNIT_PROFILES: readonly UnitProfile[] = Object.freeze([
  sharedObjectsUnitProfile,
  sectionsUnitProfile,
  identityUnitProfile,
]);

export interface NodeInstallationOptions {
  readonly network?: IdentityNetwork;
  readonly now?: () => number;
  /** How long an identity request waits for its reply (default 30 s). */
  readonly replyTimeoutMs?: number;
  /** Default: NODE_UNIT_PROFILES. */
  readonly profiles?: readonly UnitProfile[];
}

export interface NodeInstallation {
  /** The state directory. */
  readonly state: string;
  readonly installation: Installation;
  readonly storage: SqliteLfcpStorage;
  readonly secrets: FileSecretStore;
  /** What every identity flow takes: `revocationStatus({ ...node.flow, resource, url })`. */
  readonly flow: IdentityFlowOptions;
  /** Closes the database. */
  close(): void;
}

/** A reply timeout that does not keep the process alive. */
const replyTimeout = (ms: number) => () =>
  new Promise<void>((r) => {
    setTimeout(r, ms).unref();
  });

/**
 * Opens (and on the first run creates, 0700) the installation in `state`:
 * its SQLite storage, its file SecretStore, its Principal (created once)
 * and the options of the identity flows on the real network.
 */
export async function openNodeInstallation(
  state: string,
  options: NodeInstallationOptions = {},
): Promise<NodeInstallation> {
  const now = options.now ?? (() => Date.now());
  mkdirSync(state, { recursive: true, mode: 0o700 });
  const secrets = new FileSecretStore(join(state, "secrets"));
  const storage = SqliteLfcpStorage.open(join(state, "lfcp.sqlite"));
  try {
    const installation = await openInstallation(state, secrets);
    const network =
      options.network ??
      connectionNetwork({ now, timeout: replyTimeout(options.replyTimeoutMs ?? 30_000) });
    const flow: IdentityFlowOptions = {
      installation,
      storage,
      secrets,
      network,
      now,
      document: identityDocument,
      profiles: options.profiles ?? NODE_UNIT_PROFILES,
    };
    return Object.freeze({
      state,
      installation,
      storage,
      secrets,
      flow,
      close: () => storage.close(),
    });
  } catch (e) {
    storage.close();
    throw e;
  }
}
