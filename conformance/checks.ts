// Check builders shared by suite handlers (LFCP-017).

import type { Check } from "./runner.js";

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => HEX[b]).join("");

/** Bytes shown on each side of the first difference. */
const WINDOW = 16;

function excerpt(bytes: Uint8Array, offset: number): string {
  const start = Math.max(0, offset - WINDOW);
  const end = Math.min(bytes.length, offset + WINDOW);
  return `${start > 0 ? "…" : ""}${hex(bytes.subarray(start, end))}${end < bytes.length ? "…" : ""}`;
}

/** The first offset at which two byte strings differ, or -1 when equal. */
export function firstDifference(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return i;
  return a.length === b.length ? -1 : n;
}

/**
 * Byte-exact comparison. On mismatch the message gives the first differing
 * offset, both lengths and the hex around that offset on both sides.
 */
export function bytesCheck(name: string, expected: Uint8Array, actual: Uint8Array): Check {
  const at = firstDifference(expected, actual);
  if (at < 0) return { name, ok: true };
  return {
    name,
    ok: false,
    message:
      `bytes differ at offset ${at} (expected ${expected.length} bytes, actual ${actual.length})\n` +
      `      expected: ${excerpt(expected, at)}\n` +
      `      actual:   ${excerpt(actual, at)}`,
  };
}

/** Runs `fn` as one check: it passes when `fn` returns true and fails on false or a throw. */
export function check(name: string, fn: () => boolean | string): Check {
  try {
    const r = fn();
    if (r === true) return { name, ok: true };
    return { name, ok: false, message: r === false ? "check returned false" : r };
  } catch (e) {
    return { name, ok: false, message: `threw ${describeError(e)}` };
  }
}

/** Structural equality for small semantic values; the message is a short diff. */
export function equalCheck(name: string, expected: unknown, actual: unknown): Check {
  const e = stable(expected);
  const a = stable(actual);
  return e === a ? { name, ok: true } : { name, ok: false, message: `expected ${e}, actual ${a}` };
}

function stable(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) => {
    if (typeof v === "bigint") return `${v}n`;
    if (v instanceof Uint8Array) return `h'${hex(v)}'`;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>).sort(([x], [y]) => (x < y ? -1 : 1)),
      );
    }
    return v;
  });
}

export function describeError(e: unknown): string {
  if (e !== null && typeof e === "object" && "code" in e)
    return `${String((e as { code: unknown }).code)}: ${String((e as { message?: unknown }).message)}`;
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

/**
 * A negative outcome check. `actual` is the protocol code the operation
 * failed with, or null when it succeeded. `expected` is the vector's code, or
 * null when the vector requires failure without naming a code.
 */
export function outcomeCheck(name: string, expected: string | null, actual: string | null): Check {
  if (actual === null)
    return {
      name,
      ok: false,
      message: `expected ${expected ?? "a failure"}, got unexpected success`,
    };
  if (expected !== null && actual !== expected)
    return { name, ok: false, message: `expected ${expected}, actual ${actual}` };
  return { name, ok: true };
}
