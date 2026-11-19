import { fromBase64url, type PrincipalId } from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";

/** SERVICE-CONTROL-PROFILE-01: the control Resource `C` of one service installation. */
export const SERVICE_CONTROL_PROFILE_ID = "org.openlfcp.service-control.v1";

// §2 inherits SOP §8 without changing its domain: the actor is that of SOP §8 with C's Resource ID.
export { deriveActorId as deriveServiceControlActorId } from "../values.js";

/** §2.1: exactly these thirteen root keys. */
export const SERVICE_CONTROL_ROOT_KEYS = Object.freeze([
  "profile",
  "meta",
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
] as const);
export type ServiceControlRootKey = (typeof SERVICE_CONTROL_ROOT_KEYS)[number];

/** The eleven containers the initial change creates empty (§2.2). */
export type ServiceControlContainer = Exclude<ServiceControlRootKey, "profile" | "meta">;

/** Containers that are one map filled by the service, not a map of entries. */
export const WHOLE_CONTAINERS: ReadonlySet<string> = new Set(["service", "status", "lifecycle"]);

/** §6.2, in order; the last five are final. */
export const EVENT_STATES = Object.freeze([
  "received",
  "executing",
  "request-ready",
  "ready",
  "applied",
  "failed",
  "rejected",
  "stale",
  "cancelled",
] as const);
export type EventState = (typeof EVENT_STATES)[number];
export const FINAL_EVENT_STATES: ReadonlySet<string> = new Set(EVENT_STATES.slice(4));

/** §6.1: the operations version 1 defines and a version-1 service executes. */
export const SERVICE_CONTROL_V1_OPS = Object.freeze([
  "preview",
  "turn-on",
  "turn-off",
  "resume-binding",
  "remove",
  "retry-helper",
  "pause",
  "resume",
  "check",
  "pair-section",
] as const);

/** §2.1 Uuid: a UUIDv7 in lower-case hyphenated text form. */
export function isUuid7(text: unknown): text is string {
  return (
    typeof text === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(text)
  );
}

/** §2.1 Op: 1 to 32 characters of [a-z-]. Admission never refuses an unknown one (§6.1). */
export function isOp(text: unknown): text is string {
  return typeof text === "string" && /^[a-z-]{1,32}$/.test(text);
}

/** §2.1 Hash32: unpadded base64url of 32 bytes. */
export function isHash32(text: unknown): text is string {
  if (typeof text !== "string" || text.length !== 43) return false;
  try {
    return fromBase64url(text).length === 32;
  } catch {
    return false;
  }
}

const FP_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const FP_DOMAIN = Uint8Array.from("LFCP-DEVICE-FP-v1", (c) => c.charCodeAt(0));

/**
 * IDENTITY-PROFILE-01 §5.2: a device's fingerprint, the first 10 bytes of
 * SHA-256("LFCP-DEVICE-FP-v1" || id) in lower-case base32, in groups of four.
 */
export function deviceFingerprint(id: PrincipalId): string {
  const input = new Uint8Array(FP_DOMAIN.length + id.length);
  input.set(FP_DOMAIN);
  input.set(id, FP_DOMAIN.length);
  const digest = sha256(input).subarray(0, 10);
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of digest) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += FP_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return (out.match(/.{4}/g) as string[]).join("-");
}

/** §2.1 Approval. `generation` of a base approval is 0. */
export interface ServiceControlApproval {
  readonly role: "base" | "section";
  readonly resource: string;
  readonly principal: string;
  readonly certDigest: string;
  readonly certId: string;
  readonly generation: number | bigint;
  readonly origin: string;
  readonly at: string;
  /** §5 rule 3: any `revoked` value, concurrent ones included, means revoked. */
  readonly revoked: boolean;
}

export interface ServiceControlRequest {
  readonly op: string;
  readonly binding?: string;
  readonly generation?: number | bigint;
  readonly args: Readonly<Record<string, unknown>>;
  readonly client: { readonly app: string; readonly protocol: number | bigint };
  readonly at: string;
  readonly [unknownField: string]: unknown;
}

export interface ServiceControlAnswer {
  readonly qid: string;
  readonly snapshotHash: string;
  readonly choice: string;
  readonly at: string;
  readonly [unknownField: string]: unknown;
}

export interface ServiceControlCancel {
  readonly reason: "user" | "mismatch" | "expired";
  readonly at: string;
  readonly [unknownField: string]: unknown;
}

export interface ServiceControlEvent {
  /** §5 rule 3: the highest of concurrent values in the order of §6.2. */
  readonly state: EventState;
  readonly code?: string;
  readonly detail?: string;
  readonly at: string;
  readonly [unknownField: string]: unknown;
}

export interface ServiceControlQuestion {
  readonly binding: string;
  readonly generation: number | bigint;
  readonly kind: string;
  readonly anomalyId: string;
  readonly snapshotHash: string;
  readonly items: readonly string[];
  readonly counts: Readonly<Record<string, unknown>>;
  readonly actor?: string;
  readonly options: readonly string[];
  readonly at: string;
  readonly resolved?: { readonly answerId: string; readonly choice: string; readonly at: string };
  readonly superseded?: { readonly by: string };
  readonly [unknownField: string]: unknown;
}

export interface ServiceControlPairing {
  readonly descriptor: string;
  readonly principal: string;
  readonly fp: string;
  readonly [unknownField: string]: unknown;
}

/** Entries written by the service: shown as read, unknown fields included (§2.1, §11). */
export type ServiceControlRecord = Readonly<Record<string, unknown>>;
