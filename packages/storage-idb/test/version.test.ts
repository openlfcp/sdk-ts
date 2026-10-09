/// <reference lib="dom" />
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { IDB_VERSION, IdbLfcpStorage } from "../src/index.js";
import { openRaw } from "./v1-schema.js";

// LFCP-02-029: the database version. A 0.1.x database (version 1) opens
// unchanged and becomes version 2, which a 0.1.x client (opening version 1)
// refuses; a database from a newer client is refused, untouched.

let n = 0;
const name = () => `version-${++n}`;

const put = (db: IDBDatabase, store: string, key: string, value: unknown) =>
  new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });

describe("IndexedDB version (LFCP-02-029)", () => {
  it("opens a version 1 database as it is, and a 0.1.x client then refuses it", async () => {
    const db = name();
    const legacy = await openRaw(db, 1);
    await put(legacy, "routes", "a", { url: "ws://x" });
    legacy.close();
    const s = await IdbLfcpStorage.open(db);
    expect(await s.localMarks.list("")).toEqual([]);
    s.close();
    const after = await openRaw(db, IDB_VERSION);
    expect(after.version).toBe(2);
    expect(after.objectStoreNames.contains("routes")).toBe(true);
    after.close();
    await expect(openRaw(db, 1)).rejects.toMatchObject({ name: "VersionError" });
  });

  it("refuses a database of a newer client and leaves it as it is", async () => {
    const db = name();
    const newer = await openRaw(db, IDB_VERSION + 1);
    newer.close();
    await expect(IdbLfcpStorage.open(db)).rejects.toMatchObject({
      code: "UNSUPPORTED_VALUE",
      message: expect.stringContaining("newer client"),
    });
    const still = await openRaw(db, IDB_VERSION + 1);
    expect(still.version).toBe(IDB_VERSION + 1);
    still.close();
  });
});
