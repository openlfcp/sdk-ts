// The JSON view of an Identity Resource document that IDENTITY-PROFILE-TEST-
// VECTORS-01 states (`expected.state`, `inputs.entry`): scalars as values,
// uints as numbers, the concurrent values of a key as `<key>_conflict_set`,
// sorted by their JSON. Test-only: the conformance run reads the engine's
// projection through it, since the SDK exposes only validated entries.
import * as A from "@automerge/automerge";

type View = null | boolean | number | string | View[] | { [key: string]: View };

const values = (obj: unknown, key: string): unknown[] => {
  let conflicts: Record<string, unknown> | undefined;
  try {
    conflicts = A.getConflicts(obj as A.Doc<unknown>, key) as Record<string, unknown> | undefined;
  } catch {
    // A value of a conflict set is not attached to the document: no nested conflicts to read.
    conflicts = undefined;
  }
  if (conflicts !== undefined) return Object.values(conflicts);
  const value = (obj as Record<string, unknown>)[key];
  return value === undefined ? [] : [value];
};

function view(value: unknown): View {
  if (A.isImmutableString(value)) return value.toString();
  if (typeof value === "bigint") return Number(value);
  if (Array.isArray(value)) return value.map(view);
  if (value !== null && typeof value === "object") {
    const out: { [key: string]: View } = {};
    for (const key of Object.keys(value).sort()) {
      const all = values(value, key);
      if (all.length > 1)
        out[`${key}_conflict_set`] = all
          .map(view)
          .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
      else out[key] = view((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value as View;
}

/** The view of the document an Automerge save holds. */
export function identityView(save: Uint8Array): View {
  const doc = A.load(save);
  try {
    return view(doc);
  } finally {
    A.free(doc);
  }
}

/** Runs `fn` on the document an Automerge save holds, with its changes. */
export function withIdentityDocument<T>(
  save: Uint8Array,
  fn: (doc: A.Doc<unknown>, changes: Uint8Array[]) => T,
): T {
  const doc = A.load(save);
  try {
    return fn(doc, A.getAllChanges(doc));
  } finally {
    A.free(doc);
  }
}
