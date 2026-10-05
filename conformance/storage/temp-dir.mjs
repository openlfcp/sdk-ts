// Isolated temporary directories for cross-package storage tests (never a
// real LFCP data directory). JavaScript with hand-written types
// (temp-dir.d.mts), like spec.mjs: sdk-ts has no Node type definitions.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A new empty directory under the OS temporary directory. */
export function makeTempDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** Deletes a directory made by makeTempDir, with everything in it. */
export function removeTempDir(dir) {
  rmSync(dir, { recursive: true, force: true });
}

/** `dir`/`name`. */
export function inDir(dir, name) {
  return join(dir, name);
}
