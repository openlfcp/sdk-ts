// Hostile bytes on the section receive path (LFCP-02-017): a change refused
// by the SOP §11.1 checks is never expanded, and is named by its hash read
// from its bytes, the SHA-256 of its chunk from the type byte on
// (SHARED-SECTIONS-TEST-VECTORS-01 SS61 to SS63). EXP-change-rle-bomb packs
// 1,000,000 operations into about 112 bytes; decoding it after the refusal
// is the CPU and memory the limits exist to save.

import { createHash } from "node:crypto";
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
const chunkHash = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes.subarray(8)).digest("hex");
const SECTIONS_CORPUS = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";
const replica = () =>
  SectionReplica.empty({
    resource: resourceId(new Uint8Array(32).fill(7)),
    principal: principalId(new Uint8Array(32).fill(1)),
  });

describe("section receive path on hostile bytes", () => {
  it("refuses EXP-change-rle-bomb at once, names it by its hash and never decodes it", () => {
    const bomb = corpus.expansion.cases.find((c) => c.id === "EXP-change-rle-bomb");
    expect(bomb).toBeDefined();
    const bytes = hex(bomb?.bytes_hex ?? "");
    const started = performance.now();
    const out = replica().receiveChanges([bytes]);
    const ms = performance.now() - started;
    expect(out.refused).toEqual([
      expect.objectContaining({
        index: 0,
        hash: chunkHash(bytes),
        diagnostic: "INVALID_AUTOMERGE_BYTES",
      }),
    ]);
    expect(out.admitted).toEqual([]);
    expect(ms).toBeLessThan(200);
  }, 5_000);

  it("names SS61 to SS63 by the hash their cases give, each refused within 200 ms", () => {
    const cases = openSpec().readJson(SECTIONS_CORPUS) as {
      readonly cases: readonly {
        readonly id: string;
        readonly inputs: {
          readonly branches: {
            readonly A: readonly { readonly b64url: string; readonly change_hash: string }[];
          };
        };
      }[];
    };
    for (const id of ["SS61", "SS62", "SS63"]) {
      const change = cases.cases.find((c) => c.id === id)?.inputs.branches.A[0];
      expect(change, id).toBeDefined();
      const bytes = new Uint8Array(Buffer.from(change?.b64url ?? "", "base64url"));
      const started = performance.now();
      const out = replica().receiveChanges([bytes]);
      expect(performance.now() - started, id).toBeLessThan(200);
      expect(out.refused, id).toEqual([
        expect.objectContaining({
          hash: change?.change_hash,
          diagnostic: "INVALID_AUTOMERGE_BYTES",
        }),
      ]);
    }
  }, 5_000);

  it("names no hash for bytes that are not one readable change chunk, a compressed one included", () => {
    const bomb = hex(
      corpus.expansion.cases.find((c) => c.id === "EXP-change-rle-bomb")?.bytes_hex ?? "",
    );
    // Cut short: the chunk length no longer covers the bytes.
    const cut = bomb.subarray(0, bomb.length - 3);
    // Two chunks: the first is followed by trailing bytes.
    const trailing = new Uint8Array([...bomb, 0]);
    // A compressed change (chunk type 2, SS44): naming it would mean inflating it, so it is not named.
    const sections = openSpec().readJson(SECTIONS_CORPUS) as {
      readonly cases: readonly {
        readonly id: string;
        readonly inputs: {
          readonly branches: { readonly A: readonly { readonly b64url: string }[] };
        };
      }[];
    };
    const compressed = new Uint8Array(
      Buffer.from(
        sections.cases.find((c) => c.id === "SS44")?.inputs.branches.A[0]?.b64url ?? "",
        "base64url",
      ),
    );
    expect(compressed[8]).toBe(2);
    const out = replica().receiveChanges([cut, trailing, new Uint8Array([1, 2, 3]), compressed]);
    expect(out.refused.map((r) => [r.index, r.hash, r.diagnostic])).toEqual([
      [0, undefined, "INVALID_AUTOMERGE_BYTES"],
      [1, undefined, "INVALID_AUTOMERGE_BYTES"],
      [2, undefined, "INVALID_AUTOMERGE_BYTES"],
      [3, undefined, "INVALID_AUTOMERGE_BYTES"],
    ]);
  });
});
