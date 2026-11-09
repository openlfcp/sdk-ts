// FileSecretStore's directory fsync (review 414c, decision I29): Windows
// cannot open a directory for fsync (EPERM, EISDIR or EACCES), so headless
// `lfcp-node pair` could not store its first secret there. Tolerated on
// win32 only; every other platform, and every other error, still throws.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type DirectorySyncOps, syncDirectory } from "../src/secrets.js";

const failing = (code: string, at: "open" | "fsync"): DirectorySyncOps & { closed: number } => {
  const err = () => Object.assign(new Error(`${code}: operation not permitted, ${at}`), { code });
  const ops = {
    closed: 0,
    openSync: () => {
      if (at === "open") throw err();
      return 7;
    },
    fsyncSync: () => {
      if (at === "fsync") throw err();
    },
    closeSync: () => {
      ops.closed++;
    },
  };
  return ops;
};

describe("syncDirectory", () => {
  for (const code of ["EPERM", "EISDIR", "EACCES"])
    for (const at of ["open", "fsync"] as const)
      it(`tolerates ${code} at ${at} on win32 only`, () => {
        const win = failing(code, at);
        expect(() => syncDirectory("C:\\state\\secrets", "win32", win)).not.toThrow();
        expect(win.closed).toBe(at === "fsync" ? 1 : 0);
        expect(() => syncDirectory("/state/secrets", "linux", failing(code, at))).toThrow(code);
        expect(() => syncDirectory("/state/secrets", "darwin", failing(code, at))).toThrow(code);
      });

  it("throws any other error on win32", () => {
    expect(() => syncDirectory("C:\\s", "win32", failing("EIO", "fsync"))).toThrow("EIO");
    expect(() => syncDirectory("C:\\s", "win32", failing("ENOENT", "open"))).toThrow("ENOENT");
  });

  it("fsyncs a real directory on this platform", () => {
    const dir = mkdtempSync(join(tmpdir(), "lfcp-syncdir-"));
    try {
      expect(() => syncDirectory(dir)).not.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
