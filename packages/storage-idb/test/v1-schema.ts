/// <reference lib="dom" />
/**
 * The IndexedDB schema of version 1 (0.1.x, LFCP-059), frozen: the stores
 * and indexes a 0.1.x client created. Tests build legacy databases with it.
 */
export function createV1Stores(db: IDBDatabase): void {
  const plain = (name: string) => db.createObjectStore(name);
  db.createObjectStore("records").createIndex("r", "r");
  plain("heads");
  plain("conflicts");
  db.createObjectStore("epochs").createIndex("r", "r");
  const units = db.createObjectStore("units");
  units.createIndex("ras", ["r", "a", "s"]);
  units.createIndex("rst", ["r", "st"]);
  db.createObjectStore("keyPackages").createIndex("r", "r");
  const snapshots = db.createObjectStore("snapshots");
  snapshots.createIndex("r", "r");
  snapshots.createIndex("rep", ["r", "e", "p", "n"]);
  plain("resources");
  plain("routes");
  db.createObjectStore("outbound").createIndex("n", "n");
  plain("checkpoints");
  plain("syncStates");
  plain("counters");
  plain("meta");
}

/** Opens `name` at `version`, creating the version 1 stores when it is new. */
export function openRaw(name: string, version: number): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(name, version);
    open.onupgradeneeded = (e) => {
      if (e.oldVersion === 0) createV1Stores(open.result);
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}
