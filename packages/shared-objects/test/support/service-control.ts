import * as A from "@automerge/automerge";
import {
  fromBase64url,
  type PrincipalId,
  principalId,
  resourceId,
  toBase64url,
  toHex,
} from "@openlfcp/core";
import {
  deriveServiceControlActorId,
  SERVICE_CONTROL_PROFILE_ID,
} from "../../src/service-control/index.js";
import { principalRef } from "../../src/values.js";
import { descriptor } from "./identity.js";

// Deliberately invalid documents are built here too.
// biome-ignore lint/suspicious/noExplicitAny: malformed Automerge fixtures
export type Doc = Record<string, any>;

export const resource = resourceId(new Uint8Array(32).fill(9));
export const C = toBase64url(resource);
export const X = toBase64url(new Uint8Array(32).fill(10));
export const T0 = "2026-11-19T10:00:00Z";
export const uid = (n: number) => `0196f2a0-0000-7000-8000-${String(n).padStart(12, "0")}`;

export const root = principalId(new Uint8Array(32).fill(1));
export const personal = principalId(new Uint8Array(32).fill(2));
/** A kind-1 service device, B, with a valid descriptor (seed 7). */
export const serviceDevice = descriptor(7);
export const B = principalId(fromBase64url(serviceDevice.key.slice(2)));
export const secondService = descriptor(11);
export const B2 = principalId(fromBase64url(secondService.key.slice(2)));
export const other = principalId(new Uint8Array(32).fill(4));

export const actor = (signer: PrincipalId) => toHex(deriveServiceControlActorId(resource, signer));

/** Writes a plain value on a live proxy: numbers as uint, strings as ImmutableString. */
export function put(target: Doc, key: string | number, value: unknown): void {
  if (value === undefined) return;
  if (typeof value === "number") target[key] = new A.Uint(value);
  else if (typeof value === "string") target[key] = new A.ImmutableString(value);
  else if (typeof value === "boolean") target[key] = value;
  else if (Array.isArray(value)) {
    target[key] = [];
    value.forEach((v, i) => {
      put(target[key], i, v);
    });
  } else {
    target[key] = {};
    for (const [k, v] of Object.entries(value as object)) put(target[key], k, v);
  }
}

export function initial(signer: PrincipalId = root, edit?: (d: Doc) => void): A.Doc<Doc> {
  return A.change(A.init<Doc>({ actor: actor(signer) }), { time: 0 }, (d) => {
    put(d, "profile", SERVICE_CONTROL_PROFILE_ID);
    put(d, "meta", { attemptId: "attempt-1", createdAt: T0 });
    for (const k of [
      "approvals",
      "service",
      "status",
      "bindings",
      "pairing",
      "questions",
      "requests",
      "answers",
      "cancels",
      "events",
      "lifecycle",
    ])
      d[k] = {};
    edit?.(d);
  });
}

/** A change by `signer` on `doc` (a document of its causal history). */
export const edit = (doc: A.Doc<Doc>, signer: PrincipalId, fn: (d: Doc) => void): A.Doc<Doc> =>
  A.change(A.clone(doc, { actor: actor(signer) }), { time: 0 }, fn);
export const last = (doc: A.Doc<Doc>) => A.getLastLocalChange(doc) as Uint8Array;

export const approval = (who: PrincipalId, role = "base", res = C, digest = "d") => ({
  role,
  resource: res,
  principal: principalRef(who),
  certDigest: toBase64url(new Uint8Array(32).fill(digest.charCodeAt(0))),
  certId: toBase64url(new Uint8Array(32).fill(7)),
  generation: 0,
  origin: "attempt-1",
  at: T0,
});
export const SERVICE = {
  instance: "inst-1",
  kind: "apple-reminders",
  label: "MacBook Air",
  platform: "macos",
  app: "0.6.0",
  protocol: { v: 1, ops: ["check"], questionKinds: ["mass-delete"] },
  artifactSliceId: "arm64",
  macos: "15.1",
  cert: { state: "certified", manifestSeq: 1, certTestMode: false },
  capacity: { sections: 1, max: 8, devicesFree: 20 },
};
export const STATUS = { state: "running", since: T0, heartbeatAt: T0 };
export const request = (op: string, extra: Record<string, unknown> = {}) => ({
  op,
  binding: X,
  generation: 1,
  args: {},
  client: { app: "0.8.0", protocol: 1 },
  at: T0,
  ...extra,
});
export { principalRef };
