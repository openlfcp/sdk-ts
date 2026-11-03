import { afterEach, describe, expect, it, vi } from "vitest";
import { PersistentMap, put } from "../src/persistent-map.js";

// The Control State maps kept for every head share structure (review of
// #8, R8-1): a set copies only the path to its key.

const hex = (i: number) => i.toString(16).padStart(64, "0");

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PersistentMap", () => {
  it("behaves as a Map and leaves every earlier version unchanged", () => {
    const versions: PersistentMap<number>[] = [PersistentMap.empty()];
    const model = new Map<string, number>();
    let seed = 7;
    for (let i = 0; i < 3000; i++) {
      seed = (seed * 1103515245 + 12345) % 2 ** 31;
      const k = hex(seed % 1000);
      model.set(k, i);
      versions.push((versions.at(-1) as PersistentMap<number>).set(k, i));
    }
    const last = versions.at(-1) as PersistentMap<number>;
    expect(last.size).toBe(model.size);
    for (const [k, v] of model) expect(last.get(k)).toBe(v);
    expect(new Map(last)).toEqual(model);
    expect([...last.keys()].sort()).toEqual([...model.keys()].sort());
    expect(last.has(hex(5000))).toBe(false);
    expect(versions[0]?.size).toBe(0);
    expect(versions[1]?.size).toBe(1);
    expect(versions[100]?.size).toBeLessThanOrEqual(100);
  });

  it("orders keys and keeps keys of a shared prefix and suffix apart", () => {
    const a = `${"0".repeat(8)}a${"0".repeat(8)}`;
    const b = `${"0".repeat(8)}b${"0".repeat(8)}`;
    const m = PersistentMap.empty<string>().set(b, "b").set(a, "a").set(a, "A");
    expect(m.size).toBe(2);
    expect(m.get(a)).toBe("A");
    expect(m.get(b)).toBe("b");
    expect([...m.keys()]).toEqual([a, b]);
    expect(PersistentMap.from([[a, 1]]).get(b)).toBeUndefined();
  });

  it("copies only the path to the key it sets, whatever the keys (review of #8, R8-1b)", () => {
    // Keys differing only in their middle, as chosen hash collisions would.
    const chosen = (j: number) => `${"0".repeat(8)}${j.toString(16).padStart(48, "0")}a5bd9e9d`;
    let m = PersistentMap.empty<number>();
    for (let i = 0; i < 4096; i++) m = m.set(chosen(i), i);
    expect(m.height).toBeLessThanOrEqual(Math.ceil(1.45 * Math.log2(4097)));
    const freeze = vi.spyOn(Object, "freeze");
    const next = m.set(chosen(5000), 1);
    // The new node, the copied path (two more on a rotation) and the map itself.
    expect(freeze.mock.calls.length).toBeLessThanOrEqual(m.height + 4);
    expect(next.size).toBe(4097);
    expect(m.size).toBe(4096);
    expect(m.has(chosen(5000))).toBe(false);
  });

  it("put converts any other map once and shares from then on", () => {
    const plain = new Map([[hex(1), 1]]);
    const p = put(plain, hex(2), 2);
    expect(p).toBeInstanceOf(PersistentMap);
    expect(plain.size).toBe(1);
    expect(put(p, hex(3), 3).get(hex(1))).toBe(1);
  });
});
