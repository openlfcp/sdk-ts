import type * as A from "@automerge/automerge";
import { type PrincipalId, UINT64_MAX } from "@openlfcp/core";
import { pointerToken } from "../validate.js";
import { isPrincipalRef, isReverseDomain, isUtcTimestamp, principalRef } from "../values.js";
import { IdentityReader, type Value } from "./reader.js";
import {
  type DeviceEntry,
  IDENTITY_PROFILE_ID,
  type IdentityEpoch,
  isIdentityDescriptor,
  isResourceRef,
  type PairingRequest,
  type RosterEntry,
} from "./values.js";

export const IDENTITY_DIAGNOSTIC_ORDER = Object.freeze([
  "INVALID_ROOT",
  "MISSING_REQUIRED_FIELD",
  "INVALID_FIELD_TYPE",
  "INVALID_RESOURCE_REF",
  "INVALID_PRINCIPAL_REF",
  "INVALID_DESCRIPTOR",
  "INVALID_ENUM_VALUE",
  "INVALID_TIMESTAMP",
  "INVALID_EXTENSION_NAMESPACE",
] as const);
export type IdentityDiagnostic = (typeof IDENTITY_DIAGNOSTIC_ORDER)[number];

export interface IdentityProblem {
  readonly code: "PROFILE_INVALID";
  readonly diagnostic: IdentityDiagnostic;
  readonly pointer: string;
  readonly message: string;
}

export interface IdentityValidation {
  /** False only for an invalid root; invalid entries do not poison other entries. */
  readonly usable: boolean;
  readonly problems: readonly IdentityProblem[];
  readonly roster: Readonly<Record<string, RosterEntry>>;
  readonly devices: Readonly<Record<string, DeviceEntry>>;
  readonly requests: Readonly<Record<string, PairingRequest>>;
}

const at = (base: string, key: string | number) => `${base}/${pointerToken(String(key))}`;
const uint = ([type, value]: Value) =>
  type === "uint" &&
  ((typeof value === "number" && Number.isSafeInteger(value) && value >= 0) ||
    (typeof value === "bigint" && value >= 0n && value <= UINT64_MAX));

const epochOrder = (a: IdentityEpoch, b: IdentityEpoch) => (a < b ? -1 : a > b ? 1 : 0);
const textOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

class Fields {
  readonly problems = new Map<string, IdentityProblem>();
  readonly conflicts = new Set<string>();
  constructor(readonly reader: IdentityReader) {}

  fail(diagnostic: IdentityDiagnostic, pointer: string): void {
    const previous = this.problems.get(pointer);
    if (
      previous !== undefined &&
      IDENTITY_DIAGNOSTIC_ORDER.indexOf(previous.diagnostic) <=
        IDENTITY_DIAGNOSTIC_ORDER.indexOf(diagnostic)
    )
      return;
    this.problems.set(
      pointer,
      Object.freeze({
        code: "PROFILE_INVALID",
        diagnostic,
        pointer,
        message: `IDENTITY-PROFILE-01 §4: ${diagnostic} at ${pointer || "/"}`,
      }),
    );
  }

  field(obj: string, key: string, base: string, required: boolean, request: boolean): Value[] {
    const values = this.reader.all(obj, key);
    if (required && values.length === 0) this.fail("MISSING_REQUIRED_FIELD", at(base, key));
    if (request && values.length > 1) this.conflicts.add(at(base, key));
    return values;
  }

  finishEntry(base: string): void {
    const belongs = (p: string) => p === base || p.startsWith(`${base}/`);
    // §4 rule 2: report invalid values first. A conflict is INVALID_FIELD_TYPE
    // only when every concurrent value is valid on its own (including maps).
    if ([...this.problems.keys()].some(belongs)) return;
    for (const pointer of this.conflicts)
      if (belongs(pointer)) this.fail("INVALID_FIELD_TYPE", pointer);
  }

  scalar(
    values: Value[],
    type: string,
    pointer: string,
    validate?: (value: unknown) => boolean,
    diagnostic: IdentityDiagnostic = "INVALID_FIELD_TYPE",
  ): unknown {
    for (const value of values) {
      if (value[0] !== type) this.fail("INVALID_FIELD_TYPE", pointer);
      else if (validate !== undefined && !validate(value[1])) this.fail(diagnostic, pointer);
    }
    return values[0]?.[1];
  }

  list(
    values: Value[],
    pointer: string,
    type: "str" | "uint",
    request: boolean,
    resource = false,
  ): unknown[] {
    const lists: unknown[][] = [];
    for (const [kind, id] of values) {
      if (kind !== "list") {
        this.fail("INVALID_FIELD_TYPE", pointer);
        continue;
      }
      const result: unknown[] = [];
      for (const [i, entries] of this.reader.list(String(id)).entries()) {
        const pos = at(pointer, i);
        if (request && entries.length > 1) this.conflicts.add(pos);
        for (const entry of entries) {
          if (entry[0] !== type || (type === "uint" && !uint(entry)))
            this.fail("INVALID_FIELD_TYPE", pos);
          else if (resource && !isResourceRef(entry[1])) this.fail("INVALID_RESOURCE_REF", pos);
        }
        result.push(entries[0]?.[1]);
      }
      if (
        resource &&
        (result.length === 0 || result.length > 64 || new Set(result).size !== result.length)
      )
        this.fail("INVALID_FIELD_TYPE", pointer);
      lists.push(result);
    }
    return lists[0] ?? [];
  }

  entry(obj: string, key: string, table: string): Record<string, unknown> {
    const base = at(`/${table}`, key);
    const request = table === "requests";
    const roster = table === "roster";
    const output: Record<string, unknown> = {};
    if (roster ? !isResourceRef(key) : !isPrincipalRef(key))
      this.fail(roster ? "INVALID_RESOURCE_REF" : "INVALID_PRINCIPAL_REF", base);
    const required = roster
      ? ["profile", "endpoints", "coordinator"]
      : request
        ? ["descriptor", "pairing", "label", "kind"]
        : ["label", "kind"];
    const strings = roster
      ? ["profile", "coordinator", "name"]
      : request
        ? ["descriptor", "pairing", "label", "platform", "requested_at"]
        : ["label", "platform", "added_at"];
    const field = (name: string) => this.field(obj, name, base, required.includes(name), request);
    for (const name of strings) {
      const values = field(name);
      if (values.length === 0) continue;
      const pointer = at(base, name);
      output[name] = this.scalar(values, "str", pointer);
      for (const [type, value] of values) {
        if (type !== "str") continue;
        if (name === "pairing" && !isPrincipalRef(value))
          this.fail("INVALID_PRINCIPAL_REF", pointer);
        if (name === "descriptor" && !isIdentityDescriptor(String(value), key))
          this.fail("INVALID_DESCRIPTOR", pointer);
        if ((name === "added_at" || name === "requested_at") && !isUtcTimestamp(value))
          this.fail("INVALID_TIMESTAMP", pointer);
      }
    }
    if (roster)
      output.endpoints = this.list(field("endpoints"), at(base, "endpoints"), "str", false);
    else {
      const kinds = field("kind");
      if (kinds.length > 1) this.conflicts.add(at(base, "kind"));
      output.kind = this.scalar(
        kinds,
        "uint",
        at(base, "kind"),
        (v) => v === 0 || v === 1,
        "INVALID_ENUM_VALUE",
      );
      if (request) {
        const scope = this.field(
          obj,
          "scope",
          base,
          kinds.some((v) => v[1] === 1),
          true,
        );
        if (scope.length > 0) {
          if (kinds.some((v) => v[1] === 0)) this.fail("INVALID_FIELD_TYPE", at(base, "scope"));
          output.scope = this.list(scope, at(base, "scope"), "str", true, true);
        }
      }
    }
    const bool = roster ? "archived" : "revoked";
    if (!request) {
      const values = field(bool);
      if (values.length > 0) output[bool] = this.scalar(values, "boolean", at(base, bool));
    }
    if (table === "devices") {
      const values = field("missing_keys");
      const union = new Map<string, Set<IdentityEpoch>>();
      for (const [type, id] of values) {
        if (type !== "map") {
          this.fail("INVALID_FIELD_TYPE", at(base, "missing_keys"));
          continue;
        }
        for (const resource of this.reader.keys(String(id))) {
          const pointer = at(at(base, "missing_keys"), resource);
          if (!isResourceRef(resource)) this.fail("INVALID_RESOURCE_REF", pointer);
          const epochs = union.get(resource) ?? new Set<IdentityEpoch>();
          for (const list of this.reader.all(String(id), resource)) {
            this.list([list], pointer, "uint", false);
            if (list[0] === "list")
              for (const items of this.reader.list(String(list[1])))
                for (const item of items) if (uint(item)) epochs.add(item[1] as IdentityEpoch);
          }
          union.set(resource, epochs);
        }
      }
      if (values.length > 0)
        output.missing_keys = Object.freeze(
          Object.fromEntries(
            [...union]
              .sort(([a], [b]) => textOrder(a, b))
              .map(([k, v]) => [k, Object.freeze([...v].sort(epochOrder))]),
          ),
        );
    }
    // Unknown request fields are preserved/ignored too, but any conflict invalidates a request.
    if (request)
      for (const name of this.reader.keys(obj))
        if (this.reader.all(obj, name).length > 1) this.conflicts.add(at(base, name));
    for (const value of Object.values(output)) if (Array.isArray(value)) Object.freeze(value);
    return Object.freeze(output);
  }
}

/** §4: validate every concurrent value; return only usable entries, never request winners. */
export function validateIdentity(doc: A.Doc<unknown>, root: PrincipalId): IdentityValidation {
  const r = new IdentityReader(doc);
  const f = new Fields(r);
  const profiles = r.all("_root", "profile");
  if (profiles.length !== 1 || profiles[0]?.[0] !== "str" || profiles[0][1] !== IDENTITY_PROFILE_ID)
    f.fail("INVALID_ROOT", "/profile");
  for (const key of ["identity", "roster", "devices", "requests", "extensions"])
    if (r.map("_root", key) === undefined) f.fail("INVALID_ROOT", at("", key));
  const identity = r.map("_root", "identity");
  if (identity !== undefined) {
    const roots = r.all(identity, "root");
    if (roots.length !== 1 || roots[0]?.[0] !== "str" || roots[0][1] !== principalRef(root))
      f.fail("INVALID_ROOT", "/identity/root");
  }
  const usable = ![...f.problems.values()].some((p) => p.diagnostic === "INVALID_ROOT");
  const extensions = r.map("_root", "extensions");
  if (extensions !== undefined)
    for (const key of r.keys(extensions))
      if (!isReverseDomain(key)) f.fail("INVALID_EXTENSION_NAMESPACE", at("/extensions", key));
  const tables: Record<string, Record<string, unknown>> = {};
  for (const table of ["roster", "devices", "requests"]) {
    const entries: [string, unknown][] = [];
    const container = r.map("_root", table);
    if (container !== undefined)
      for (const key of r.keys(container)) {
        const base = at(`/${table}`, key);
        const values = r.all(container, key);
        if (table === "requests" && values.length > 1) f.conflicts.add(base);
        const projections: Record<string, unknown>[] = [];
        for (const [type, id] of values) {
          if (type !== "map") f.fail("INVALID_FIELD_TYPE", base);
          else projections.push(f.entry(String(id), key, table));
        }
        // Concurrent device maps also cannot disagree about kind; hints union across maps.
        if (table === "devices" && new Set(projections.map((p) => p.kind)).size > 1)
          f.conflicts.add(at(base, "kind"));
        f.finishEntry(base);
        if (usable && ![...f.problems.keys()].some((p) => p === base || p.startsWith(`${base}/`))) {
          const first = projections[0];
          if (first !== undefined) {
            if (table === "devices" && projections.some((p) => p.missing_keys !== undefined)) {
              const union = new Map<string, Set<IdentityEpoch>>();
              for (const p of projections)
                for (const [ref, epochs] of Object.entries(
                  (p.missing_keys ?? {}) as Record<string, IdentityEpoch[]>,
                ))
                  union.set(ref, new Set([...(union.get(ref) ?? []), ...epochs]));
              entries.push([
                key,
                Object.freeze({
                  ...first,
                  missing_keys: Object.freeze(
                    Object.fromEntries(
                      [...union]
                        .sort(([a], [b]) => textOrder(a, b))
                        .map(([k, v]) => [k, Object.freeze([...v].sort(epochOrder))]),
                    ),
                  ),
                }),
              ]);
            } else entries.push([key, first]);
          }
        }
      }
    tables[table] = Object.freeze(Object.fromEntries(entries));
  }
  return Object.freeze({
    usable,
    problems: Object.freeze(
      [...f.problems.values()].sort(
        (a, b) =>
          IDENTITY_DIAGNOSTIC_ORDER.indexOf(a.diagnostic) -
            IDENTITY_DIAGNOSTIC_ORDER.indexOf(b.diagnostic) || textOrder(a.pointer, b.pointer),
      ),
    ),
    roster: tables.roster as Record<string, RosterEntry>,
    devices: tables.devices as Record<string, DeviceEntry>,
    requests: tables.requests as Record<string, PairingRequest>,
  });
}
