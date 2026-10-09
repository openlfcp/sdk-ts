// The canonical (SHARED-OBJECTS-PROFILE-01 §11.3) and references (§11.4)
// sections of the Automerge reference corpus, from mvp-0.2-baseline.2 on,
// through the sdk-ts admission. A canonical case: the change alone passes
// or fails the admission check (checkChange). A references case: the
// history is admitted, then the change is admitted or refused, and a
// refused change leaves a replica that still saves and loads at the same
// heads. Cases admission-pending.json lists must still fail (their fix is
// pending); every other case must pass. At an earlier baseline the
// sections are absent and nothing runs.

import { fromHex, principalId, resourceId } from "@openlfcp/core";
import { checkChange, SharedObjectsReplica } from "@openlfcp/shared-objects";
import { describe, expect, it } from "vitest";
import pending from "./admission-pending.json" with { type: "json" };
import { readCorpus } from "./corpus.js";

interface AdmissionCase {
  readonly id: string;
  readonly history_hex?: readonly string[];
  readonly change_hex: string;
  readonly expected: { readonly canonical?: boolean; readonly admitted?: boolean };
}
const corpus = readCorpus() as unknown as {
  readonly resource_hex: string;
  readonly canonical?: { readonly cases: readonly AdmissionCase[] };
  readonly references?: { readonly cases: readonly AdmissionCase[] };
};
const R = resourceId(fromHex(corpus.resource_hex));
const opts = { resource: R, principal: principalId(new Uint8Array(32).fill(0xf1)) };
const isPending = new Set<string>(pending.cases);

/** Whether the sdk-ts admission decides `c` as the corpus expects; a string says why not. */
function canonicalOutcome(c: AdmissionCase): true | string {
  let passes: boolean;
  try {
    checkChange(fromHex(c.change_hex));
    passes = true;
  } catch {
    passes = false;
  }
  return passes === c.expected.canonical ? true : `checkChange ${passes ? "passes" : "refuses"} it`;
}

function referencesOutcome(c: AdmissionCase): true | string {
  try {
    const r = SharedObjectsReplica.empty(opts);
    const history = r.receiveChanges((c.history_hex ?? []).map((h) => checkChange(fromHex(h))));
    if (history.refused.length > 0 || history.waiting.length > 0)
      return "its history is not admitted";
    const heads = r.heads().join();
    let admitted: boolean;
    try {
      const out = r.receiveChanges([checkChange(fromHex(c.change_hex))]);
      admitted = out.refused.length === 0 && out.waiting.length === 0;
    } catch {
      admitted = false;
    }
    if (admitted !== c.expected.admitted) return admitted ? "admitted" : "refused";
    if (!admitted) {
      if (r.heads().join() !== heads) return "the refused change changed the heads";
      const loaded = SharedObjectsReplica.fromSave(r.save(), opts);
      if (loaded.heads().join() !== heads) return "the replica does not load at its heads";
    }
    return true;
  } catch (e) {
    return `threw ${e instanceof Error ? e.message : String(e)}`;
  }
}

for (const [section, cases, outcome] of [
  ["canonical (§11.3)", corpus.canonical?.cases, canonicalOutcome],
  ["references (§11.4)", corpus.references?.cases, referencesOutcome],
] as const)
  describe(`Automerge corpus ${section}`, () => {
    if (cases === undefined) {
      it("is not in this baseline", () => expect(cases).toBeUndefined());
      return;
    }
    for (const c of cases)
      it(`${c.id}${isPending.has(c.id) ? " (pending: still fails)" : ""}`, () => {
        const result = outcome(c);
        if (isPending.has(c.id))
          expect(result, `${c.id} passes now: remove it from admission-pending.json`).not.toBe(
            true,
          );
        else expect(result).toBe(true);
      });
  });

it("lists only cases of the corpus as pending", () => {
  if (corpus.canonical === undefined) return;
  const ids = new Set(
    [...(corpus.canonical?.cases ?? []), ...(corpus.references?.cases ?? [])].map((c) => c.id),
  );
  expect(pending.cases.filter((id) => !ids.has(id))).toEqual([]);
});
