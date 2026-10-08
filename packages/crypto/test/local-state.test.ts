import { describe, expect, it } from "vitest";
import {
  exportLocalStateKey,
  isSealedLocal,
  LocalStateKey,
  localEnvelopeGeneration,
  openLocal,
  sealLocal,
} from "../src/index.js";

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const AAD = ascii("install-1|checkpoints|r1");
const TEXT = ascii("Prepare contract: a private Task title");

describe("local state envelopes (LFCP-02-098)", () => {
  it("round-trips, with the magic and generation in front", () => {
    const key = LocalStateKey.generate();
    const sealed = sealLocal(key, 3, AAD, TEXT);
    expect(isSealedLocal(sealed)).toBe(true);
    expect(localEnvelopeGeneration(sealed)).toBe(3);
    expect(Array.from(sealed.subarray(0, 4))).toEqual(Array.from(ascii("lse1")));
    expect(sealed.length).toBe(8 + 24 + TEXT.length + 16);
    expect(openLocal(key, AAD, sealed)).toEqual(TEXT);
  });

  it("uses a fresh nonce for every write", () => {
    const key = LocalStateKey.generate();
    const a = sealLocal(key, 1, AAD, TEXT);
    const b = sealLocal(key, 1, AAD, TEXT);
    expect(a).not.toEqual(b);
    expect(a.subarray(8, 32)).not.toEqual(b.subarray(8, 32));
  });

  it("refuses another key, another AAD, another generation and tampered bytes", () => {
    const key = LocalStateKey.generate();
    const sealed = sealLocal(key, 1, AAD, TEXT);
    const fails = (k: LocalStateKey, aad: Uint8Array, bytes: Uint8Array) =>
      expect(() => openLocal(k, aad, bytes)).toThrow(
        expect.objectContaining({ code: "AEAD_AUTHENTICATION_FAILED" }),
      );
    fails(LocalStateKey.generate(), AAD, sealed);
    fails(key, ascii("install-2|checkpoints|r1"), sealed);
    const regenerated = Uint8Array.from(sealed);
    regenerated[7] = 2; // the generation in the header
    fails(key, AAD, regenerated);
    const tampered = Uint8Array.from(sealed);
    tampered[40] = (tampered[40] as number) ^ 1;
    fails(key, AAD, tampered);
    fails(key, AAD, TEXT); // plaintext is not an envelope
  });

  it("tells plaintext from envelopes", () => {
    // An Automerge save starts with its magic bytes, never "lse1".
    expect(isSealedLocal(Uint8Array.from([0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0]))).toBe(false);
    expect(isSealedLocal(ascii("lse1"))).toBe(false); // too short for a header, nonce and tag
    expect(localEnvelopeGeneration(TEXT)).toBeUndefined();
  });

  it("keeps the key redacted and exports it only on request", () => {
    const key = LocalStateKey.generate();
    expect(JSON.stringify({ key })).toBe('{"key":"[redacted]"}');
    expect(String(key)).toBe("[redacted]");
    const bytes = exportLocalStateKey(key);
    expect(bytes).toHaveLength(32);
    const again = LocalStateKey.import(bytes);
    expect(openLocal(again, AAD, sealLocal(key, 1, AAD, TEXT))).toEqual(TEXT);
    expect(() => LocalStateKey.import(new Uint8Array(31))).toThrow(
      expect.objectContaining({ code: "INVALID_LENGTH" }),
    );
    expect(() => sealLocal(key, 0, AAD, TEXT)).toThrow(
      expect.objectContaining({ code: "UNSUPPORTED_VALUE" }),
    );
  });
});
