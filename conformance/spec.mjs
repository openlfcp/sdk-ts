// Reads official openlfcp/spec files at the commit pinned in spec.lock (LFCP-017).
//
// Vectors are never copied into sdk-ts. Every file is read with
// `git -C <spec checkout> show <commit>:<path>`, so the checkout's working
// tree and current branch do not matter. The checkout is $LFCP_SPEC_DIR, or
// ../spec next to sdk-ts; a relative LFCP_SPEC_DIR resolves from the sdk-ts
// root. Before reading anything, openSpec checks that the locked tag still
// resolves to the locked commit, and throws a clear error if not.
//
// Test-only Node code: it lives outside the portable packages on purpose.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** The sdk-ts repository root. */
export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Runs `git -C dir ...args` and returns stdout as bytes; throws with git's stderr on failure. */
export function runGit(dir, args) {
  try {
    // The section corpus alone is several MiB; execFileSync's default buffer is 1 MiB.
    return new Uint8Array(
      execFileSync("git", ["-C", dir, ...args], { stdio: "pipe", maxBuffer: 256 * 1024 * 1024 }),
    );
  } catch (e) {
    const stderr = e.stderr ? String(e.stderr).trim() : String(e.message ?? e);
    throw new Error(`git ${args.join(" ")} failed in ${dir}: ${stderr}`);
  }
}

/** Parses and checks spec.lock text. */
export function parseSpecLock(text, where = "spec.lock") {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch (e) {
    throw new Error(`${where} is not JSON: ${e.message}`);
  }
  for (const field of ["repository", "tag", "commit"]) {
    if (typeof lock?.[field] !== "string" || lock[field] === "")
      throw new Error(`${where} has no string field "${field}"`);
  }
  if (!/^[0-9a-f]{40}$/.test(lock.commit))
    throw new Error(`${where} must pin a full lowercase 40-hex commit, got "${lock.commit}"`);
  return { repository: lock.repository, tag: lock.tag, commit: lock.commit };
}

/**
 * Opens the spec checkout and verifies it against the lock.
 * `options` exist for the runner's self-tests: lock (instead of spec.lock),
 * specDir (instead of LFCP_SPEC_DIR) and git (instead of runGit).
 */
export function openSpec(options = {}) {
  const lock =
    options.lock ?? parseSpecLock(readFileSync(join(ROOT, "spec.lock"), "utf8"), "spec.lock");
  const dir = resolve(ROOT, options.specDir ?? process.env.LFCP_SPEC_DIR ?? "../spec");
  const git = options.git ?? runGit;

  let resolved;
  try {
    resolved = new TextDecoder()
      .decode(git(dir, ["rev-parse", "--verify", "--quiet", `refs/tags/${lock.tag}^{commit}`]))
      .trim();
  } catch (e) {
    throw new Error(
      `spec.lock pins tag ${lock.tag}, but it does not resolve in the spec checkout at ${dir} ` +
        `(${e.message}). Clone ${lock.repository} there with its tags, or set LFCP_SPEC_DIR.`,
    );
  }
  if (resolved !== lock.commit) {
    throw new Error(
      `spec tag ${lock.tag} in ${dir} resolves to ${resolved || "nothing"}, but spec.lock pins ` +
        `${lock.commit}. Tags are never moved, so the checkout or spec.lock is wrong.`,
    );
  }

  return reader(lock, dir, git);
}

/** Reads files at `lock.commit` of the checkout at `dir`; `allowed(path)` limits what may be read. */
function reader(lock, dir, git, allowed = () => true) {
  const guard = (path) => {
    if (!allowed(path)) throw new Error(`${path} is outside the files this lock pins`);
  };
  const read = (path) => {
    guard(path);
    try {
      return git(dir, ["show", `${lock.commit}:${path}`]);
    } catch (e) {
      throw new Error(`cannot read ${path} at spec commit ${lock.commit}: ${e.message}`);
    }
  };
  const list = (path) => {
    guard(`${path.replace(/\/+$/, "")}/`);
    const tree = `${lock.commit}:${path.replace(/\/+$/, "")}`;
    let text;
    try {
      text = new TextDecoder().decode(git(dir, ["ls-tree", "--name-only", tree]));
    } catch (e) {
      throw new Error(`cannot list ${path} at spec commit ${lock.commit}: ${e.message}`);
    }
    return text.split("\n").filter(Boolean).sort();
  };
  return {
    lock,
    dir,
    list,
    read,
    readText: (path) => new TextDecoder("utf-8", { fatal: true }).decode(read(path)),
    readJson: (path) => {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(read(path));
      try {
        return JSON.parse(text);
      } catch (e) {
        throw new Error(`${path} at spec commit ${lock.commit} is not JSON: ${e.message}`);
      }
    },
  };
}

/** The status of a development pin (spec-sections.lock). */
export const DEV_PIN_STATUS = "dev-pin-pre-baseline";

/**
 * The spec files spec-sections.lock pins: the shared sections corpus and
 * its two documents. Everything else comes from spec.lock.
 */
export const SECTIONS_PATHS = Object.freeze([
  "test-vectors/shared-sections-01/",
  "profiles/SHARED-SECTIONS-PROFILE-01.md",
  "integration/MARKDOWN-SECTIONS-01.md",
]);

/** Parses and checks spec-sections.lock text: a commit, no tag, and the dev pin status. */
export function parseSpecSectionsLock(text, where = "spec-sections.lock") {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch (e) {
    throw new Error(`${where} is not JSON: ${e.message}`);
  }
  for (const field of ["repository", "commit", "status"]) {
    if (typeof lock?.[field] !== "string" || lock[field] === "")
      throw new Error(`${where} has no string field "${field}"`);
  }
  if (!/^[0-9a-f]{40}$/.test(lock.commit))
    throw new Error(`${where} must pin a full lowercase 40-hex commit, got "${lock.commit}"`);
  if (lock.status !== DEV_PIN_STATUS)
    throw new Error(`${where} status must be "${DEV_PIN_STATUS}", got "${lock.status}"`);
  if ("tag" in lock) throw new Error(`${where} pins a commit, not a tag; use spec.lock for a tag`);
  return { repository: lock.repository, commit: lock.commit, status: lock.status };
}

/**
 * Opens the spec checkout at the development pin of the shared sections
 * corpus (spec-sections.lock), before the first MVP 0.2 baseline tag. The
 * pinned commit must exist in the checkout; there is no tag to check. Only
 * SECTIONS_PATHS can be read. The options are those of openSpec.
 */
export function openSpecSections(options = {}) {
  const lock =
    options.lock ??
    parseSpecSectionsLock(
      readFileSync(join(ROOT, "spec-sections.lock"), "utf8"),
      "spec-sections.lock",
    );
  const dir = resolve(ROOT, options.specDir ?? process.env.LFCP_SPEC_DIR ?? "../spec");
  const git = options.git ?? runGit;
  try {
    git(dir, ["cat-file", "-e", `${lock.commit}^{commit}`]);
  } catch (e) {
    throw new Error(
      `spec-sections.lock pins commit ${lock.commit}, but the spec checkout at ${dir} does not ` +
        `have it (${e.message}). Fetch ${lock.repository} there, or set LFCP_SPEC_DIR.`,
    );
  }
  const allowed = (path) =>
    SECTIONS_PATHS.some((p) => (p.endsWith("/") ? path.startsWith(p) : path === p));
  return reader(lock, dir, git, allowed);
}

/** Prints one line to stdout (the portable packages have no console typing). */
export function log(line) {
  process.stdout.write(`${line}\n`);
}

/** Writes a machine-readable summary under conformance/.results/ (gitignored); returns its repository-relative path. */
export function writeSummary(name, summary) {
  const dir = join(ROOT, "conformance", ".results");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${name}.json`), `${JSON.stringify(summary, null, 2)}\n`);
  return `conformance/.results/${name}.json`;
}

/** A text file of this repository (for source-level checks), by repository-relative path. */
export function readRepoText(path) {
  return readFileSync(join(ROOT, path), "utf8");
}
