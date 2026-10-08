// Self-tests for the spec loader (LFCP-017), with an injected git.

import { describe, expect, it } from "vitest";
import {
  type Git,
  openSpec,
  openSpecSections,
  parseSpecLock,
  parseSpecSectionsLock,
} from "./spec.mjs";

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
    if (args[0] === "ls-tree") {
      const [commit, dir] = String(args[2]).split(":");
      if (commit !== LOCK.commit) throw new Error("fatal: bad object");
      const names = Object.keys(files)
        .filter((p) => p.startsWith(`${dir}/`))
        .map((p) => p.slice((dir as string).length + 1));
      return bytes(names.join("\n"));
    }
    if (args[0] === "cat-file") {
      if (args[2] !== `${LOCK.commit}^{commit}`) throw new Error("fatal: Not a valid object name");
      return bytes("");
    }
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

  it("lists a directory at the locked commit, sorted", () => {
    const spec = openSpec({
      lock: LOCK,
      specDir: "/x",
      git: fakeGit(LOCK.commit, { "d/b.json": "{}", "d/a.json": "{}", "e/c.json": "{}" }),
    });
    expect(spec.list("d")).toEqual(["a.json", "b.json"]);
    expect(spec.list("d/")).toEqual(["a.json", "b.json"]);
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

describe("spec-sections.lock loader", () => {
  const DEV = {
    repository: "openlfcp/spec",
    commit: LOCK.commit,
    status: "dev-pin-pre-baseline",
  } as const;
  const CORPUS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

  it("reads the section corpus at a commit without a tag", () => {
    const spec = openSpecSections({
      lock: DEV,
      specDir: "/x",
      git: fakeGit(undefined, { [CORPUS]: '{"cases":[]}' }),
    });
    expect(spec.readJson(CORPUS)).toEqual({ cases: [] });
    expect(spec.list("test-vectors/shared-sections-01")).toEqual([
      "SHARED-SECTIONS-TEST-VECTORS-01.json",
    ]);
  });

  it("reads nothing outside the section corpus", () => {
    const spec = openSpecSections({ lock: DEV, specDir: "/x", git: fakeGit(undefined) });
    expect(() => spec.read("wire/LFCP-WIRE-01.md")).toThrow("outside the files this lock pins");
    expect(() => spec.list("test-vectors")).toThrow("outside the files this lock pins");
  });

  it("fails clearly when the checkout lacks the commit", () => {
    expect(() =>
      openSpecSections({
        lock: { ...DEV, commit: "2".repeat(40) },
        specDir: "/x",
        git: fakeGit(undefined),
      }),
    ).toThrow(`spec-sections.lock pins commit ${"2".repeat(40)}, but the spec checkout at /x`);
  });

  it("validates spec-sections.lock", () => {
    expect(parseSpecSectionsLock(JSON.stringify(DEV))).toEqual(DEV);
    expect(() => parseSpecSectionsLock(JSON.stringify({ ...DEV, status: "x" }))).toThrow(
      'status must be "dev-pin-pre-baseline"',
    );
    expect(() => parseSpecSectionsLock(JSON.stringify({ ...DEV, tag: "t" }))).toThrow(
      "pins a commit, not a tag",
    );
    expect(() => parseSpecSectionsLock(JSON.stringify({ ...DEV, commit: "abc" }))).toThrow(
      "must pin a full lowercase 40-hex commit",
    );
  });

  it("pins a commit that exists in the spec checkout", () => {
    const spec = openSpecSections();
    expect(spec.lock.status).toBe("dev-pin-pre-baseline");
    expect(spec.list("test-vectors/shared-sections-01")).toContain(
      "SHARED-SECTIONS-TEST-VECTORS-01.json",
    );
  });
});
