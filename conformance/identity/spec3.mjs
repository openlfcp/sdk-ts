// Reads the identity corpora of openlfcp/spec PR #3 (branch identity-01-vectors)
// at a pinned commit, until they are published in mvp-0.4-baseline.1 and
// spec.lock moves there (IDENTITY-PROFILE-01 §11). Files are read with
// `git -C <spec checkout> show <commit>:<path>`, like spec.mjs; the checkout
// is $LFCP_SPEC_DIR or ../spec and must have fetched the commit.

import { resolve } from "node:path";
import { ROOT, runGit } from "../spec.mjs";

export const IDENTITY_SPEC = Object.freeze({
  repository: "openlfcp/spec",
  ref: "identity-01-vectors (spec#3)",
  commit: "ff812626080dbbaa168287eb4fe1de05cc4b35de",
});

export const WIRE_IDENTITY = "test-vectors/lfcp-wire-01/LFCP-IDENTITY-TEST-VECTORS-01.json";
export const PROFILE_IDENTITY = "test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.json";
export const FLOW_FIXTURES = "test-vectors/identity-01/IDENTITY-FLOW-FIXTURES-01.json";

const cache = new Map();

/** The JSON file `path` at the pinned spec#3 commit. */
export function readIdentityJson(path) {
  let v = cache.get(path);
  if (v !== undefined) return v;
  const dir = resolve(ROOT, process.env.LFCP_SPEC_DIR ?? "../spec");
  let bytes;
  try {
    bytes = runGit(dir, ["show", `${IDENTITY_SPEC.commit}:${path}`]);
  } catch (e) {
    throw new Error(
      `cannot read ${path} at ${IDENTITY_SPEC.ref} ${IDENTITY_SPEC.commit} in ${dir}; ` +
        `fetch openlfcp/spec there (git fetch origin identity-01-vectors) or set LFCP_SPEC_DIR: ${e.message}`,
    );
  }
  v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  cache.set(path, v);
  return v;
}
