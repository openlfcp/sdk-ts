import { describe, expect, it } from "vitest";
import {
  InMemorySecretStore,
  type LocalStateCipher,
  LocalStateKeyring,
  type LocalStateMeta,
  localStateKeyRef,
  type ResealRow,
  reseal,
} from "../src/index.js";

/**
 * A stand-in cipher with the envelope's shape and its bindings (key, AAD,
 * generation), and no cryptography: this package may not depend on
 * @openlfcp/crypto, whose localStateCipher is tested there and end to end in
 * conformance/storage.
 */
let nextKey = 0;
const same = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((x, i) => x === b[i]);
const fakeCipher: LocalStateCipher<number> = {
  generateKey: () => ++nextKey,
  importKey: (bytes) => new DataView(bytes.buffer, bytes.byteOffset).getUint32(0),
  exportKey: (key) => {
    const out = new Uint8Array(32);
    new DataView(out.buffer).setUint32(0, key);
    return out;
  },
  seal: (key, generation, aad, plaintext) => {
    const out = new Uint8Array(12 + 4 + aad.length + plaintext.length + 16);
    const view = new DataView(out.buffer);
    out.set([0x6c, 0x73, 0x65, 0x31]);
    view.setUint32(4, generation);
    view.setUint32(8, key);
    view.setUint32(12, aad.length);
    out.set(aad, 16);
    out.set(plaintext, 16 + aad.length);
    return out;
  },
  open: (key, aad, envelope) => {
    const view = new DataView(envelope.buffer, envelope.byteOffset);
    const length = view.getUint32(12);
    if (view.getUint32(8) !== key || !same(envelope.subarray(16, 16 + length), aad))
      throw new Error("does not authenticate");
    return envelope.slice(16 + length, envelope.length - 16);
  },
  isSealed: (bytes) => bytes.length >= 32 && bytes[0] === 0x6c && bytes[3] === 0x31,
  generationOf: (bytes) =>
    fakeCipher.isSealed(bytes)
      ? new DataView(bytes.buffer, bytes.byteOffset).getUint32(4)
      : undefined,
};

const NOW = "2026-10-09T00:00:00Z";
const LATER = "2026-10-10T00:00:00Z";
const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);

describe("local state keyring (LFCP-02-098)", () => {
  it("creates the key of a new install before anything is sealed", async () => {
    const secrets = new InMemorySecretStore();
    const ring = await LocalStateKeyring.prepare(fakeCipher, secrets, undefined, NOW);
    expect(ring.meta).toMatchObject({
      scheme: "lse-v1",
      generation: 1,
      phase: "migrating",
      previous: null,
      lastEvent: { kind: "created", at: NOW },
    });
    expect(ring.meta.installId).toMatch(/^[0-9a-f]{32}$/);
    expect(await secrets.get(localStateKeyRef(ring.meta.installId, 1))).toHaveLength(32);
    const sealed = ring.seal("checkpoints", "r1", text("Task title"));
    expect(ring.open("checkpoints", "r1", sealed)).toMatchObject({ kind: "opened", generation: 1 });
    expect(read((ring.open("checkpoints", "r1", sealed) as { bytes: Uint8Array }).bytes)).toBe(
      "Task title",
    );
    expect(JSON.stringify(ring)).toBe('"[LocalStateKeyring]"');
  });

  it("binds a row to its store and key, and passes plaintext through", async () => {
    const ring = await LocalStateKeyring.prepare(
      fakeCipher,
      new InMemorySecretStore(),
      undefined,
      NOW,
    );
    const sealed = ring.seal("checkpoints", "r1", text("Task title"));
    expect(ring.open("checkpoints", "r2", sealed)).toEqual({
      kind: "unreadable",
      reason: "authentication",
    });
    expect(ring.open("journal", "r1", sealed).kind).toBe("unreadable");
    expect(ring.open("checkpoints", "r1", text("legacy")).kind).toBe("plain");
  });

  it("reopens with the stored key, and survives a lost key with the next generation", async () => {
    const secrets = new InMemorySecretStore();
    const first = (await LocalStateKeyring.prepare(fakeCipher, secrets, undefined, NOW)).finished(
      NOW,
    );
    expect(first.meta).toMatchObject({ phase: "ready", lastEvent: { kind: "migrated" } });
    const sealed = first.seal("checkpoints", "r1", text("Task title"));
    const again = await LocalStateKeyring.prepare(fakeCipher, secrets, first.meta, LATER);
    expect(again.meta).toEqual(first.meta);
    expect(again.open("checkpoints", "r1", sealed).kind).toBe("opened");

    await secrets.delete(localStateKeyRef(first.meta.installId, 1));
    const lost = await LocalStateKeyring.prepare(fakeCipher, secrets, first.meta, LATER);
    expect(lost.meta).toMatchObject({
      generation: 2,
      phase: "ready",
      lastEvent: { kind: "key-lost", at: LATER },
    });
    expect(lost.open("checkpoints", "r1", sealed)).toEqual({
      kind: "unreadable",
      reason: "missing-key",
    });
    expect(lost.needsReseal(sealed)).toBe(false); // left as it is, replaced when rewritten
    const resealed = lost.seal("checkpoints", "r1", text("rebuilt"));
    expect(lost.open("checkpoints", "r1", resealed).kind).toBe("opened");
    // An empty value marks a deleted secret (a store without delete).
    await secrets.put(localStateKeyRef(first.meta.installId, 2), new Uint8Array(0));
    const meta: LocalStateMeta = lost.meta;
    expect(
      (await LocalStateKeyring.prepare(fakeCipher, secrets, meta, LATER)).meta.generation,
    ).toBe(3);
  });

  it("rotates: the old generation still opens until the rows are sealed again", async () => {
    const secrets = new InMemorySecretStore();
    const ring = (await LocalStateKeyring.prepare(fakeCipher, secrets, undefined, NOW)).finished(
      NOW,
    );
    const old = ring.seal("checkpoints", "r1", text("Task title"));
    const rotating = await ring.rotate(secrets, LATER);
    expect(rotating.meta).toMatchObject({ generation: 2, phase: "rotating", previous: 1 });
    expect(rotating.open("checkpoints", "r1", old).kind).toBe("opened");
    expect(rotating.needsReseal(old)).toBe(true);
    // A crash mid-rotation: the next open holds both keys.
    const resumed = await LocalStateKeyring.prepare(fakeCipher, secrets, rotating.meta, LATER);
    expect(resumed.open("checkpoints", "r1", old).kind).toBe("opened");
    expect(resumed.retired).toBe(localStateKeyRef(ring.meta.installId, 1));
    const done = resumed.finished(LATER);
    expect(done.meta).toMatchObject({ phase: "ready", previous: null, generation: 2 });
    expect(done.open("checkpoints", "r1", old).kind).toBe("unreadable");
    await expect(done.rotate(secrets, LATER)).resolves.toBeDefined();
    await expect(rotating.rotate(secrets, LATER)).rejects.toMatchObject({
      code: "UNSUPPORTED_VALUE",
    });
  });

  it("seals rows in resumable batches", async () => {
    const secrets = new InMemorySecretStore();
    const ring = await LocalStateKeyring.prepare(fakeCipher, secrets, undefined, NOW);
    const rows = new Map<string, Uint8Array>(
      ["a", "b", "c", "d", "e"].map((k) => [k, text(`state of ${k}`)]),
    );
    rows.set("c", ring.seal("checkpoints", "c", text("state of c")));
    const scan = async (after: string | null, limit: number): Promise<ResealRow[]> =>
      [...rows.keys()]
        .sort()
        .filter((k) => after === null || k > after)
        .slice(0, limit)
        .map((key) => ({ store: "checkpoints", key, bytes: rows.get(key) as Uint8Array }));
    let writes = 0;
    const write = async (sealed: readonly ResealRow[]) => {
      writes++;
      for (const r of sealed) rows.set(r.key, r.bytes);
    };
    expect(await reseal(ring, scan, write, 2)).toBe(4);
    expect(writes).toBe(3);
    for (const [key, bytes] of rows) {
      const opened = ring.open("checkpoints", key, bytes);
      expect(opened.kind).toBe("opened");
      expect(read((opened as { bytes: Uint8Array }).bytes)).toBe(`state of ${key}`);
    }
    expect(await reseal(ring, scan, write, 2)).toBe(0); // nothing left: resumable
  });
});
