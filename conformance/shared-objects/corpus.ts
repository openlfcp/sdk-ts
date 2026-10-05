// The SHARED-OBJECTS-TEST-VECTORS-01 Automerge reference corpus
// (SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json), generated with
// @automerge/automerge 3.5.0. It is supplementary, not byte-normative
// (SHARED-OBJECTS-PROFILE-01 §14): a conforming binding applies its
// changes, loads its save images and reaches its logical state and
// conflict sets.

import { openSpec, runGit } from "../spec.mjs";

/**
 * The spec commit that holds the corpus and its fixed generator. It is not
 * in the pinned baseline mvp-0.1-baseline.3 (spec.lock): it lands in
 * baseline.4. The orchestrator approved this pin for the LFCP-031/032 tests.
 * TODO(baseline.4): read the corpus at the spec.lock commit once sdk-ts
 * moves to mvp-0.1-baseline.4, and drop this constant.
 */
export const CORPUS_SPEC_COMMIT = "e25b1eaab4dc6ace873309bff688f29bc9d38db8";
export const CORPUS_PATH =
  "test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json";

export interface CorpusChange {
  readonly label: string;
  readonly actor: string;
  readonly actor_hex: string;
  readonly seq: number;
  readonly hash: string;
  readonly deps: readonly string[];
  readonly change_hex: string;
  readonly change_sha256: string;
}

export interface CorpusScenario {
  readonly id: string;
  readonly description: string;
  readonly changes: readonly CorpusChange[];
  readonly heads: readonly string[];
  readonly save_hex: string;
  readonly save_sha256: string;
  readonly state: unknown;
  /** conflicts[object][field] = sorted values; conflicts[object][""] = concurrent objects under one ID. */
  readonly conflicts: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly snapshot?: { readonly save_hex: string; readonly heads: readonly string[] };
}

export interface Corpus {
  readonly automerge_version: string;
  readonly profile: string;
  readonly resource_hex: string;
  readonly actors: Readonly<Record<string, string>>;
  readonly scenarios: readonly CorpusScenario[];
}

// The WHATWG TextDecoder global (sdk-ts compiles without DOM or Node types).
declare const TextDecoder: new (
  label: string,
  options: { fatal: boolean },
) => { decode(bytes: Uint8Array): string };

let cached: Corpus | undefined;

/** The corpus at CORPUS_SPEC_COMMIT, from the same spec checkout as the suite. */
export function readCorpus(): Corpus {
  if (cached === undefined) {
    const spec = openSpec();
    const bytes = runGit(spec.dir, ["show", `${CORPUS_SPEC_COMMIT}:${CORPUS_PATH}`]);
    cached = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Corpus;
  }
  return cached;
}

export const corpusScenario = (id: string): CorpusScenario => {
  const s = readCorpus().scenarios.find((x) => x.id === id);
  if (s === undefined) throw new Error(`the corpus has no scenario ${id}`);
  return s;
};
