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
    return new Uint8Array(execFileSync("git", ["-C", dir, ...args], { stdio: "pipe" }));
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

  const read = (path) => {
    try {
      return git(dir, ["show", `${lock.commit}:${path}`]);
    } catch (e) {
      throw new Error(`cannot read ${path} at spec commit ${lock.commit}: ${e.message}`);
    }
  };
  return {
    lock,
    dir,
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
