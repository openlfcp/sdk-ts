import * as A from "@automerge/automerge";
import { LfcpError } from "@openlfcp/core";
import { checkChange, checkSaveHeader } from "../admission/framing.js";
import {
  checkChangeExpansion,
  checkSnapshotExpansion,
  SNAPSHOT_LIMITS_FLOOR,
  type SnapshotLimits,
} from "../admission/limits.js";
import { ProfileInvalidError } from "../profile-invalid.js";
import type { Json } from "../validate.js";
import { type SectionValidation, validateSection } from "./schema.js";

/**
 * A loaded SHARED-SECTIONS-PROFILE-01 document, read-only: what a Resource
 * whose Genesis names org.openlfcp.shared-sections.v1 is read as (§1,
 * profileModel). Loading checks the inherited SOP framing and limits before
 * the engine sees any byte (§2, §16.1).
 *
 * Not yet here: the section admission rules A1–A5 (§14.1), the effective
 * tree (§7) and the intents (§11), which later tasks add. fromChanges
 * therefore loads changes a receiver has already admitted, such as its own
 * persisted history; it is not a receive path.
 */

/** An Automerge datatype as the backend reports it: "str", "text", "map", "list", "boolean", "int", … */
export type ValueType = string;

export class SectionDocument {
  readonly #doc: A.Doc<unknown>;

  private constructor(doc: A.Doc<unknown>) {
    this.#doc = doc;
  }

  /**
   * Loads an Automerge full save: a Snapshot image checked against `limits`
   * (SOP §13.1, at least the floor), or this device's own persisted state
   * ("local-state"). Throws PROFILE_INVALID / INVALID_AUTOMERGE_BYTES.
   */
  static fromSave(
    save: Uint8Array,
    limits: SnapshotLimits | "local-state" = SNAPSHOT_LIMITS_FLOOR,
  ): SectionDocument {
    checkSaveHeader(save);
    if (limits !== "local-state") checkSnapshotExpansion(save, limits);
    try {
      return new SectionDocument(A.load(save));
    } catch (e) {
      if (e instanceof LfcpError) throw e;
      throw new ProfileInvalidError(
        "INVALID_AUTOMERGE_BYTES",
        `invalid Automerge save (SOP §13): ${(e as Error).message}`,
      );
    }
  }

  /**
   * The document of exactly an admitted change set, in any order. Each
   * change passes the SOP §11 and §11.1 byte checks first (throws
   * PROFILE_INVALID / INVALID_AUTOMERGE_BYTES). Changes whose dependencies
   * are not in the set are returned by hash as unapplied.
   */
  static fromChanges(changes: Iterable<Uint8Array>): {
    readonly document: SectionDocument;
    readonly unapplied: readonly string[];
  } {
    const checked = [...changes].map((bytes) => {
      checkChangeExpansion(bytes);
      return checkChange(bytes);
    });
    const [doc] = A.applyChanges(
      A.init<unknown>(),
      checked.map((c) => c.bytes),
    );
    const unapplied = checked.filter((c) => !A.hasHeads(doc, [c.hash])).map((c) => c.hash);
    return Object.freeze({
      document: new SectionDocument(doc),
      unapplied: Object.freeze(unapplied),
    });
  }

  /** The current heads, sorted. */
  heads(): string[] {
    return [...A.getHeads(this.#doc)].sort();
  }

  /** The full save of the document. */
  save(): Uint8Array {
    return A.save(this.#doc);
  }

  /** §3, §4, §14.2: the schema validation of the current state. */
  validate(): SectionValidation {
    return validateSection(this.#doc);
  }

  /**
   * The datatype of every concurrent value at `path` from the root (map
   * keys and list indexes), none when absent. Tells a scalar string ("str")
   * from collaborative Text ("text"), which a JSON reading cannot (§2).
   */
  valueTypes(path: readonly (string | number)[]): ValueType[] {
    const backend = A.getBackend(this.#doc);
    const heads = A.getHeads(this.#doc);
    let obj = "_root";
    for (const [i, prop] of path.entries()) {
      const values = backend.getAll(obj, prop, heads) as unknown[][];
      if (i === path.length - 1) return values.map((v) => v[0] as string);
      const only = values.length === 1 ? values[0] : undefined;
      if (only === undefined || !["map", "list", "text"].includes(only[0] as string)) return [];
      obj = only[1] as string;
    }
    return ["map"];
  }

  /** The current state as JSON: scalar strings and Text both read as strings. */
  toJSON(): Json {
    return plain(this.#doc);
  }
}

function plain(value: unknown): Json {
  if (A.isImmutableString(value)) return value.toString();
  if (value instanceof A.Counter) return value.value;
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === "object" && !(value instanceof Uint8Array))
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
  return value as Json;
}
