// `lfcp-node pair` arguments and usage (LFCP-04-412). The pairing itself
// runs against the reference server in
// conformance/interop/rust-server-pair-cli.test.ts.

import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  FileSecretStore,
  main,
  openInstallation,
  PAIR_EXIT,
  parsePairArguments,
} from "../src/index.js";

const base = ["lfcp://pair/x", "--state", "/s", "--label", "bridge"];

describe("lfcp-node pair arguments", () => {
  it("a service device with its sections, by default", () => {
    expect(parsePairArguments([...base, "--section", "Notes", "--section", "Tasks"])).toEqual({
      link: "lfcp://pair/x",
      state: "/s",
      label: "bridge",
      kind: 1,
      sections: ["Notes", "Tasks"],
      platform: "server",
      wait: 600,
      poll: 5,
    });
  });

  it("a personal device takes no sections; the times are whole seconds", () => {
    expect(parsePairArguments([...base, "--personal", "--wait", "0", "--poll", "2"])).toMatchObject(
      {
        kind: 0,
        sections: [],
        wait: 0,
        poll: 2,
      },
    );
    expect(parsePairArguments([...base, "--personal", "--section", "Notes"])).toBe(
      "--section is for a service device only",
    );
    expect(parsePairArguments([...base, "--section", "N", "--wait", "1.5"])).toBe(
      "--wait needs whole seconds",
    );
    expect(parsePairArguments([...base, "--section", "N", "--poll", "0"])).toBe(
      "--poll needs at least one second",
    );
  });

  it("refuses what it cannot run", () => {
    expect(parsePairArguments([...base])).toBe(
      "a service device needs at least one --section (or --personal)",
    );
    expect(parsePairArguments(["--state", "/s", "--label", "b", "--section", "N"])).toBe(
      "the pairing link is missing",
    );
    expect(parsePairArguments([...base, "--section", "N", "x"])).toBe("one link only");
    expect(parsePairArguments([...base, "--section", "N", "--force"])).toBe(
      "unknown option --force",
    );
  });

  it("main prints the usage for anything but pair, and for bad arguments", async () => {
    const lines: string[] = [];
    expect(await main(["status"], { out: (l) => lines.push(l) })).toBe(PAIR_EXIT.USAGE);
    expect(await main(["pair"], { out: (l) => lines.push(l) })).toBe(PAIR_EXIT.USAGE);
    expect(lines.join("\n")).toContain("usage: lfcp-node pair <link|->");
    expect(lines.join("\n")).toContain("the pairing link is missing");
  });
});

describe("the installation of a state directory", () => {
  it("is created once, its keys in the SecretStore, its ID public", async () => {
    const dir = mkdtempSync(join(tmpdir(), "lfcp-installation-"));
    try {
      const secrets = new FileSecretStore(join(dir, "secrets"));
      const a = await openInstallation(dir, secrets);
      const b = await openInstallation(dir, secrets);
      expect(b.signer.descriptor).toEqual(a.signer.descriptor);
      const file = join(dir, "installation.json");
      // POSIX permissions: Windows has no mode bits to check.
      if (process.platform !== "win32") expect(statSync(file).mode & 0o777).toBe(0o600);
      // The file names the Principal; the keys are only in the SecretStore.
      expect(Object.keys(JSON.parse(readFileSync(file, "utf8")))).toEqual(["principal"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
