import { toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import {
  exportSecretKeyBytes,
  InvitationSecret,
  importAgreementKey,
  importSigningKey,
} from "../src/index.js";

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const SCALAR = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);

describe("InvitationSecret (LFCP-WIRE-01 §18.2)", () => {
  it("holds the Invitation Principal's two key pairs", () => {
    const s = InvitationSecret.fromKeys(importSigningKey(SEED), importAgreementKey(SCALAR));
    expect(toHex(exportSecretKeyBytes(s.signingKey))).toBe(toHex(SEED));
    expect(toHex(exportSecretKeyBytes(s.agreementKey))).toBe(toHex(SCALAR));
  });

  it("prints [redacted] and has no own properties", () => {
    const s = InvitationSecret.generate();
    expect(JSON.stringify(s)).toBe('"[redacted]"');
    expect(`${s}`).toBe("[redacted]");
    const inspect = (s as unknown as Record<symbol, () => string>)[
      Symbol.for("nodejs.util.inspect.custom")
    ];
    expect(inspect?.call(s)).toBe("[redacted]");
    expect(Object.getOwnPropertyNames(s)).toEqual([]);
    expect(Object.keys({ ...s })).toEqual([]);
  });

  it("generates independent keys every time", () => {
    const [a, b] = [InvitationSecret.generate(), InvitationSecret.generate()];
    expect(toHex(a.signingKey.publicKey)).not.toBe(toHex(b.signingKey.publicKey));
    expect(toHex(a.agreementKey.publicKey)).not.toBe(toHex(b.agreementKey.publicKey));
  });
});
