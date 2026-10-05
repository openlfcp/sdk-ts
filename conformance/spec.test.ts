// Self-tests for the spec loader (LFCP-017), with an injected git.

import { describe, expect, it } from "vitest";
import { type Git, openSpec, parseSpecLock } from "./spec.mjs";

const LOCK = {
  repository: "openlfcp/spec",
  tag: "synthetic-tag",
  commit: "1".repeat(40),
};
const bytes = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

/** A fake git whose tag resolves to `resolved` (or fails when undefined). */
const fakeGit =
  (resolved: string | undefined, files: Record<string, string> = {}): Git =>
  (_dir, args) => {
    if (args[0] === "rev-parse") {
      if (resolved === undefined) throw new Error("fatal: Needed a single revision");
      return bytes(`${resolved}\n`);
    }
    const [commit, path] = String(args[1]).split(":");
    const file = commit === LOCK.commit && path !== undefined ? files[path] : undefined;
    if (file === undefined) throw new Error(`fatal: path '${path}' does not exist`);
    return bytes(file);
  };

describe("spec loader", () => {
  it("reads files at the locked commit after checking the tag", () => {
    const spec = openSpec({
      lock: LOCK,
      specDir: "/x",
      git: fakeGit(LOCK.commit, { "a.json": '{"n":1}' }),
    });
    expect(spec.readJson("a.json")).toEqual({ n: 1 });
  });

  it("fails clearly when the tag resolves to another commit", () => {
    expect(() => openSpec({ lock: LOCK, specDir: "/x", git: fakeGit("2".repeat(40)) })).toThrow(
      `spec tag synthetic-tag in /x resolves to ${"2".repeat(40)}, but spec.lock pins ${LOCK.commit}`,
    );
  });

  it("fails clearly when the tag is missing", () => {
    expect(() => openSpec({ lock: LOCK, specDir: "/x", git: fakeGit(undefined) })).toThrow(
      "spec.lock pins tag synthetic-tag, but it does not resolve in the spec checkout at /x",
    );
  });

  it("names the path and commit when a file is missing", () => {
    const spec = openSpec({ lock: LOCK, specDir: "/x", git: fakeGit(LOCK.commit) });
    expect(() => spec.read("missing.json")).toThrow(
      `cannot read missing.json at spec commit ${LOCK.commit}`,
    );
  });

  it("validates spec.lock", () => {
    expect(parseSpecLock(JSON.stringify(LOCK))).toEqual(LOCK);
    expect(() => parseSpecLock("{")).toThrow("spec.lock is not JSON");
    expect(() => parseSpecLock(JSON.stringify({ ...LOCK, tag: "" }))).toThrow(
      'no string field "tag"',
    );
    expect(() => parseSpecLock(JSON.stringify({ ...LOCK, commit: "abc" }))).toThrow(
      "must pin a full lowercase 40-hex commit",
    );
  });
});
