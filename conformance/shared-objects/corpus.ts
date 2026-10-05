// The SHARED-OBJECTS-TEST-VECTORS-01 Automerge reference corpus
// (SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json), generated with
// @automerge/automerge 3.5.0, read at the spec commit pinned in spec.lock
// (part of the baseline since mvp-0.1-baseline.4). It is supplementary,
// not byte-normative (SHARED-OBJECTS-PROFILE-01 §14): a conforming binding
// applies its changes, loads its save images and reaches its logical state
// and conflict sets, and rejects its negatives.

import { openSpec } from "../spec.mjs";

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

/** A Data Unit plaintext a receiver must reject, on top of a scenario's state. */
export interface CorpusNegative {
  readonly id: string;
  readonly description: string;
  readonly rule: string;
  readonly base_scenario: string;
  /** The fixture Principal that signs the Data Unit carrying the plaintext. */
  readonly signer: string;
  readonly signer_actor_hex: string;
  readonly change: CorpusChange;
  readonly plaintext_hex: string;
  readonly expected: {
    readonly valid: false;
    readonly disposition: string;
    readonly error: { readonly code: string; readonly diagnostic?: string };
  };
}

export interface Corpus {
  readonly automerge_version: string;
  readonly profile: string;
  readonly resource_hex: string;
  readonly actors: Readonly<Record<string, string>>;
  readonly scenarios: readonly CorpusScenario[];
  readonly negatives: readonly CorpusNegative[];
}

let cached: Corpus | undefined;

/** The corpus at the spec.lock commit, from the same spec checkout as the suite. */
export function readCorpus(): Corpus {
  if (cached === undefined) cached = openSpec().readJson(CORPUS_PATH) as Corpus;
  return cached;
}

export const corpusScenario = (id: string): CorpusScenario => {
  const s = readCorpus().scenarios.find((x) => x.id === id);
  if (s === undefined) throw new Error(`the corpus has no scenario ${id}`);
  return s;
};
