// openNodeInstallation (504, spike B-001 gap G3): the installation of a state
// directory, as `lfcp-node pair` made it, with the identity flow options.

import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { toHex } from "@openlfcp/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NODE_UNIT_PROFILES, openNodeInstallation } from "../src/index.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "lfcp-node-installation-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("openNodeInstallation", () => {
  it("creates the installation once and reopens the same Principal, with the flow options", async () => {
    const state = join(dir, "bridge");
    const a = await openNodeInstallation(state, { now: () => 42 });
    const id = toHex(a.installation.signer.descriptor.principalId);
    expect(existsSync(join(state, "lfcp.sqlite"))).toBe(true);
    expect(existsSync(join(state, "installation.json"))).toBe(true);
    expect(a.flow.installation).toBe(a.installation);
    expect(a.flow.storage).toBe(a.storage);
    expect(a.flow.secrets).toBe(a.secrets);
    expect(a.flow.now()).toBe(42);
    expect(a.flow.profiles).toBe(NODE_UNIT_PROFILES);
    expect(NODE_UNIT_PROFILES.map((p) => p.dataProfile).sort()).toEqual([
      "org.openlfcp.identity.v1",
      "org.openlfcp.shared-objects.v1",
      "org.openlfcp.shared-sections.v1",
    ]);
    expect(await a.storage.resources.list()).toEqual([]);
    a.close();
    const b = await openNodeInstallation(state);
    expect(toHex(b.installation.signer.descriptor.principalId)).toBe(id);
    b.close();
  });
});
