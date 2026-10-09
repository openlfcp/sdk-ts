import * as A from "@automerge/automerge";
import { describe, expect, it } from "vitest";
import { checkCanonicalChange } from "../src/admission/canonical.js";
import { ProfileInvalidError } from "../src/profile-invalid.js";
import { ACTOR, type Doc, documents, OTHER, rng } from "./support/automerge-docs.js";

// SHARED-OBJECTS-PROFILE-01 §11.3 (SPEC-PATCH-10, ADR 0010): the canonical
// encoding walk against Automerge's own writing (differential) and against
// mutated bytes (whatever it accepts, Automerge writes back the same). The
// spec's corpus (canonical, SS59) runs in conformance/.

const CHANGES = documents(12).flatMap((d) => A.getAllChanges(d));

describe("§11.3 the canonical encoding", () => {
  it("every change Automerge writes is canonical, and the walk reads what the engine decodes", () => {
    expect(CHANGES.length).toBeGreaterThan(200);
    for (const bytes of CHANGES) {
      const parsed = checkCanonicalChange(bytes);
      const d = A.decodeChange(bytes);
      expect(parsed.actor).toBe(d.actor);
      expect(parsed.seq).toBe(d.seq);
      expect(parsed.startOp).toBe(d.startOp);
      expect([...parsed.deps]).toEqual([...d.deps].sort());
      expect(parsed.ops.length).toBe(d.ops.length);
      parsed.ops.forEach((op, i) => {
        const e = d.ops[i] as unknown as {
          obj: string;
          pred: string[];
          elemId?: string;
          key?: string;
          insert?: boolean;
        };
        expect(op.obj).toBe(e.obj);
        expect(op.insert).toBe(e.insert === true);
        expect([...op.pred]).toEqual([...e.pred]);
        if (op.key.kind === "prop") expect(op.key.name).toBe(e.key);
        else expect(op.key.kind === "head" ? "_head" : op.key.id).toBe(e.elemId);
      });
    }
  });

  it("mutated bytes: whatever the walk accepts, Automerge writes back byte for byte", () => {
    const r = rng(99);
    let accepted = 0;
    let refused = 0;
    for (let n = 0; n < 4000; n++) {
      const base = CHANGES[Math.floor(r() * CHANGES.length)] as Uint8Array;
      const bytes = Uint8Array.from(base);
      const flips = 1 + Math.floor(r() * 3);
      for (let f = 0; f < flips; f++) {
        // Past the magic, checksum and chunk type: those are the framing's.
        const at = 9 + Math.floor(r() * (bytes.length - 9));
        bytes[at] = Math.floor(r() * 256);
      }
      try {
        checkCanonicalChange(bytes);
      } catch (e) {
        expect(e).toBeInstanceOf(ProfileInvalidError);
        refused++;
        continue;
      }
      // Automerge JS's own round trip is not exact for floats (NaN payloads, -0)
      // and cannot take byte values back: those changes are not compared here.
      const decoded = A.decodeChange(bytes);
      if (decoded.ops.some((o) => typeof o.value === "number" && !Number.isSafeInteger(o.value)))
        continue;
      let again: Uint8Array;
      try {
        again = A.encodeChange(decoded);
      } catch {
        continue;
      }
      accepted++;
      // The checksum (bytes 4-8) is the framing's to verify.
      expect(Buffer.from(again.subarray(8)).equals(Buffer.from(bytes.subarray(8)))).toBe(true);
    }
    expect(refused).toBeGreaterThan(1000);
    expect(accepted).toBeGreaterThan(0);
  });

  it("a non-shortest number and unsorted dependencies are refused", () => {
    let a: Doc = A.init({ actor: ACTOR });
    a = A.change(a, (d) => {
      d.x = 1;
    });
    let b: Doc = A.clone(a, { actor: OTHER });
    b = A.change(b, (d) => {
      d.y = 2;
    });
    a = A.change(a, (d) => {
      d.z = 3;
    });
    const m = A.change(A.merge(a, b), (d) => {
      d.x = 4;
    });
    const last = A.getLastLocalChange(m) as Uint8Array;
    // Dependencies in descending order (Automerge's encoder sorts them, so swap the bytes),
    // after the chunk length (a LEB128 of one or two bytes here) and the dependency count.
    const countAt = 9 + ((last[9] as number) & 0x80 ? 2 : 1);
    expect(last[countAt]).toBe(2);
    const depsAt = countAt + 1;
    const swapped = Uint8Array.from(last);
    swapped.set(last.subarray(depsAt + 32, depsAt + 64), depsAt);
    swapped.set(last.subarray(depsAt, depsAt + 32), depsAt + 32);
    expect(() => checkCanonicalChange(swapped)).toThrow(/not strictly ascending/);
    // A seq written in two bytes (0x81 0x00 is 1): the header is no longer shortest.
    const plain = A.getAllChanges(a)[0] as Uint8Array;
    expect(A.decodeChange(plain).seq).toBe(1);
    // After the chunk length (one byte), no dependencies, the actor's length and the actor.
    const seqAt = 9 + 1 + 1 + 1 + 32;
    expect(plain[seqAt]).toBe(1);
    const padded = new Uint8Array(plain.length + 1);
    padded.set(plain.subarray(0, seqAt));
    padded.set([0x81, 0x00], seqAt);
    padded.set(plain.subarray(seqAt + 1), seqAt + 2);
    padded[9] = (plain[9] as number) + 1;
    expect(() => checkCanonicalChange(padded)).toThrow(/shortest/);
  });
});

describe("the walk on its own", () => {
  it("refuses a run of more rows than a change may hold without expanding it", () => {
    // A change chunk whose action column is one null run of 2^60 rows.
    const body = [0x00, 0x01, 0xaa, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x42, 0x0a];
    const run = [0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10];
    const content = [...body, ...run];
    const bytes = Uint8Array.from([
      0x85,
      0x6f,
      0x4a,
      0x83,
      0,
      0,
      0,
      0,
      1,
      content.length,
      ...content,
    ]);
    const started = Date.now();
    expect(() => checkCanonicalChange(bytes)).toThrow(/more rows than a change may/);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
