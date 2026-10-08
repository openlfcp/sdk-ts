// Hostile bytes on the section receive path (LFCP-02-017): a change refused
// by the SOP §11.1 checks is never expanded afterwards, not even to name
// its hash. EXP-change-rle-bomb packs 1,000,000 operations into about 112
// bytes; decoding it after the refusal is the CPU the limits exist to save.

import { principalId, resourceId } from "@openlfcp/core";
import { SectionReplica } from "@openlfcp/shared-objects/sections";
import { describe, expect, it } from "vitest";
import { openSpec } from "../spec.mjs";

const SOP_CORPUS = "test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json";
const corpus = openSpec().readJson(SOP_CORPUS) as {
  readonly expansion: {
    readonly cases: readonly { readonly id: string; readonly bytes_hex: string }[];
  };
};
const hex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (b) => Number.parseInt(b, 16));

describe("section receive path on hostile bytes", () => {
  it("refuses EXP-change-rle-bomb at once and never decodes it", () => {
    const bomb = corpus.expansion.cases.find((c) => c.id === "EXP-change-rle-bomb");
    expect(bomb).toBeDefined();
    const r = SectionReplica.empty({
      resource: resourceId(new Uint8Array(32).fill(7)),
      principal: principalId(new Uint8Array(32).fill(1)),
    });
    const started = performance.now();
    const out = r.receiveChanges([hex(bomb?.bytes_hex ?? "")]);
    const ms = performance.now() - started;
    expect(out.refused).toEqual([
      expect.objectContaining({ index: 0, hash: undefined, diagnostic: "INVALID_AUTOMERGE_BYTES" }),
    ]);
    expect(out.admitted).toEqual([]);
    expect(ms).toBeLessThan(200);
  }, 5_000);
});
