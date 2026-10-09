// Writes the legacy storage fixtures of LFCP-02-029 with the released
// v0.1.3 code: one owner's Shared Objects Resource with a Task and three
// local edits still queued (pending offline work), its profile checkpoint,
// Control Chain, epoch-0 DEK and its reference. Once in SQLite with file
// secrets (storage-node), once in IndexedDB (storage-idb on
// fake-indexeddb), dumped to JSON. Synthetic keys only.
//
//   node conformance/upgrade/make-fixture-0.1.3.mjs <v0.1.3 checkout> <out dir>
//
// The checkout is a clone of sdk-ts at tag v0.1.3, installed and built
// (pnpm install --frozen-lockfile && pnpm build). The committed fixtures in
// fixtures/0.1.3 were made this way; the test never runs old code.

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [checkout, out] = process.argv.slice(2).map((p) => resolve(p));
if (checkout === undefined || out === undefined) {
  console.error("usage: make-fixture-0.1.3.mjs <v0.1.3 checkout> <out dir>");
  process.exit(2);
}
const pkg = (name, file = "dist/index.js") =>
  import(pathToFileURL(join(checkout, "packages", name, file)).href);
const core = await pkg("core");
const crypto = await pkg("crypto");
const wire = await pkg("wire");
const storage = await pkg("storage");
const client = await pkg("client");
const so = await pkg("shared-objects");
const node = await pkg("storage-node");
const idb = await pkg("storage-idb");
const { IDBFactory, IDBKeyRange } = await import(
  pathToFileURL(
    join(checkout, "packages/storage-idb/node_modules/fake-indexeddb/build/esm/index.js"),
  ).href
);

globalThis.IDBKeyRange ??= IDBKeyRange;

const bytes32 = (from) => Uint8Array.from({ length: 32 }, (_, i) => (from + i) & 0xff);
const key = crypto.importSigningKey(bytes32(1));
const agreement = crypto.importAgreementKey(bytes32(101));
const OWNER = { key, descriptor: wire.principalDescriptorFromKeys(key, agreement) };
const R = core.resourceId(bytes32(240));
const DEK = crypto.importResourceDEK(bytes32(150));
const URL = "ws://127.0.0.1:1/v1/ws";
const TASK = "0192e4a0-0000-7000-8000-000000000010";

/** Fills `store` (an LfcpStorage) and `secrets` with the legacy state. */
async function fill(st, secrets) {
  const genesis = wire.signControlRecord(
    { resourceId: R, controlSeq: 0n, prevControlId: null },
    {
      type: "GENESIS",
      dataProfile: so.PROFILE_ID,
      owner: OWNER.descriptor,
      dekCommitment: crypto.dekCommitment(R, core.dataEpoch(0n), DEK),
      endpoints: [{ url: URL, priority: 0n }],
      coordinatorUrl: URL,
    },
    OWNER,
  );
  const chain = wire.validateControlChain([genesis.bytes]);
  await client.saveControlChain(st, chain, null);
  const ref = storage.dekSecretRef(R, core.dataEpoch(0n));
  await secrets.put(ref, crypto.exportSecretKeyBytes(DEK));
  const e0 = (await st.control.epochs(R))[0];
  await st.commit([{ op: "put-epoch", resourceId: R, epoch: { ...e0, dekRef: ref } }]);
  const principal = OWNER.descriptor.principalId;
  const { replica, change } = so.SharedObjectsReplica.create({ resource: R, principal });
  const profile = new so.SharedObjectsDataProfile(replica);
  const checkpointer = new client.ProfileCheckpointer(st, profile, { minIntervalMs: 0 });
  const write = async (local) =>
    client.createQueuedDataUnit(
      st,
      {
        view: chain,
        controlHead: chain.state.head,
        actor: OWNER,
        dek: DEK,
        profile: profile.codecFor({ resourceId: R, actor: principal }),
        value: so.checkChange(local.change),
        onCreated: (created, value) => profile.recordLocal(created.unitId, value),
      },
      () => [checkpointer.write()],
    );
  await write(change);
  const task = so.createTask({ id: TASK, title: "Legacy task", createdBy: principal });
  await write(profile.replica.apply(task.intent));
  const current = profile.replica.task(TASK).task;
  await write(profile.replica.apply(so.setStatus(current, "in_progress").intent));
}

mkdirSync(out, { recursive: true });

// SQLite and file secrets.
const sqlite = node.SqliteLfcpStorage.open(join(out, "lfcp.sqlite3"));
await fill(sqlite, new node.FileSecretStore(join(out, "secrets")));
sqlite.close();

// IndexedDB, dumped store by store (keys and structured values as JSON).
const factory = new IDBFactory();
const db = await idb.IdbLfcpStorage.open("legacy", { indexedDB: factory });
const secrets = new storage.InMemorySecretStore();
await fill(db, secrets);
db.close?.();
const enc = (v) =>
  v instanceof Uint8Array
    ? { $bytes: Buffer.from(v).toString("hex") }
    : typeof v === "bigint"
      ? { $bigint: v.toString() }
      : Array.isArray(v)
        ? v.map(enc)
        : v !== null && typeof v === "object"
          ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, enc(x)]))
          : v;
const raw = await new Promise((ok, no) => {
  const r = factory.open("legacy");
  r.onsuccess = () => ok(r.result);
  r.onerror = () => no(r.error);
});
const dump = { name: "legacy", version: raw.version, stores: {} };
for (const name of raw.objectStoreNames) {
  const tx = raw.transaction(name, "readonly");
  const store = tx.objectStore(name);
  const [keys, values] = await Promise.all(
    [store.getAllKeys(), store.getAll()].map(
      (q) =>
        new Promise((ok, no) => {
          q.onsuccess = () => ok(q.result);
          q.onerror = () => no(q.error);
        }),
    ),
  );
  dump.stores[name] = keys.map((k, i) => [enc(k), enc(values[i])]);
}
raw.close();
const secretRows = [];
for (const ref of [storage.dekSecretRef(R, core.dataEpoch(0n))])
  secretRows.push([ref, Buffer.from(await secrets.get(ref)).toString("hex")]);
dump.secrets = secretRows;
writeFileSync(join(out, "idb.json"), `${JSON.stringify(dump, null, 1)}\n`);
console.log(`fixtures written to ${out}`);
