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

  it("keeps keys of equal hashes apart", () => {
    // Equal length, first and last eight units: the same hash.
    const a = `${"0".repeat(8)}a${"0".repeat(8)}`;
    const b = `${"0".repeat(8)}b${"0".repeat(8)}`;
    const m = PersistentMap.empty<string>().set(a, "a").set(b, "b").set(a, "A");
    expect(m.size).toBe(2);
    expect(m.get(a)).toBe("A");
    expect(m.get(b)).toBe("b");
    expect(PersistentMap.from([[a, 1]]).get(b)).toBeUndefined();
  });

  it("copies only the path to the key it sets", () => {
    let m = PersistentMap.empty<number>();
    for (let i = 0; i < 4096; i++) m = m.set(hex(i), i);
    const freeze = vi.spyOn(Object, "freeze");
    const next = m.set(hex(5000), 1);
    // The leaf, its bucket, at most seven branches and the map itself.
    expect(freeze.mock.calls.length).toBeLessThanOrEqual(10);
    expect(next.size).toBe(4097);
    expect(m.size).toBe(4096);
    expect(m.has(hex(5000))).toBe(false);
  });

  it("put converts any other map once and shares from then on", () => {
    const plain = new Map([[hex(1), 1]]);
    const p = put(plain, hex(2), 2);
    expect(p).toBeInstanceOf(PersistentMap);
    expect(plain.size).toBe(1);
    expect(put(p, hex(3), 3).get(hex(1))).toBe(1);
  });
});
