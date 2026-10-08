# @openlfcp/storage-idb

Durable portable storage for LFCP clients (LFCP-059): `IdbLfcpStorage`, the
`LfcpStorage` interface of `@openlfcp/storage` on IndexedDB. It runs in
browsers, Electron (Obsidian desktop) and mobile WebViews. It uses no Node
built-ins (`scripts/check-boundaries.mjs`), and it passes the shared contract
suite (`runStorageContract` from `@openlfcp/storage/contract`).

```ts
const storage = await IdbLfcpStorage.open(`openlfcp-v1-${installId}`, {
  onReserved: ({ kind, key, value }) => mirrorHighWater(kind, key, value),
});
// ... storage.commit([...]), storage.dataUnits.get(id), ...
storage.close();
```

The application names the database. Use one per client install: an IndexedDB
origin is often shared (all Obsidian vaults share `app://obsidian.md`), and two
installs must never share sequence counters.

## Scope

Part of the OpenLFCP TypeScript SDK, which implements the OpenLFCP MVP 0.1
subset of [LFCP-WIRE-01](https://github.com/openlfcp/spec/blob/main/wire/LFCP-WIRE-01.md)
at `mvp-0.1-baseline.9`, not every deferred WIRE-01 feature. It does not
claim full LFCP-WIRE-01 conformance. This is the MVP 0.1 release
(`0.1.1`, npm dist-tag `latest`). Until 1.0, minor versions may change APIs.

## Guarantees

- **Atomicity.** One `commit()` is one readwrite transaction over every object
  store. The Control Head compare-and-set is read inside it, and any failure
  aborts the whole transaction: every write or none.
- **Durability.** Every readwrite transaction asks for `durability: "strict"`
  (Chromium's default is `relaxed`), and every promise resolves only on the
  transaction's `complete` event.
- **Sequences.** A reservation reads its counter, checks it against this
  Principal's own stored units or Snapshots, and writes it, all in one strict
  transaction. A counter behind them fails closed with `SEQUENCE_REUSE`. A
  value is returned only after its transaction completed, and only after
  `onReserved` returned. If `onReserved` throws, the value is abandoned and
  never reissued.
- **Exact bytes.** Control Records, Data Units, Key Packages and Snapshots are
  stored as their exact bytes; the other fields are indexes. Storing an ID again
  with other bytes fails the batch. Values come out as frozen copies.
- **No foreign awaits.** A transaction awaits only IndexedDB requests, so it
  cannot auto-commit half way.

`counters()` lists the reservation counters (`actor:<resource>:<principal>`,
`snapshot:<resource>:<epoch>:<publisher>`). `meta.get`/`meta.put` keep small,
durable application metadata, such as an install marker. Never put secrets
there: secrets belong in a `SecretStore`.

## Limits

- **Strict durability is the runtime's promise, not ours.** The tests run on
  [fake-indexeddb](https://github.com/dumbmatter/fakeIndexedDB) (6.2.5, a test
  dependency only). The tests check that every readwrite transaction asks for
  `strict`, but they cannot show that a real browser flushed to disk. How
  durable the data is depends on the browser's IndexedDB implementation and
  the device's storage.
- **Eviction.** Browsers may evict IndexedDB under storage pressure unless the
  origin's storage is persistent. Applications should call
  `navigator.storage.persist()` and tell the user when it is denied. An
  evicted database loses the sequence counters, so the application must not
  keep writing as the same Principal (for example, check an install marker
  kept elsewhere).
- **One writer.** IndexedDB transactions serialize the reservations, but two
  application instances writing the same database is not a supported
  configuration. Hold a Web Lock (`navigator.locks`) for the lifetime of the
  writer.
- **Plaintext.** Profile checkpoints are plaintext CRDT state. They are
  protected at rest only by the runtime's profile directory.

## Links

- Specification: [openlfcp/spec](https://github.com/openlfcp/spec)
- Source and the other SDK packages: [openlfcp/sdk-ts](https://github.com/openlfcp/sdk-ts)
- Issues: [openlfcp/sdk-ts/issues](https://github.com/openlfcp/sdk-ts/issues)

## License

Apache-2.0. See [LICENSE](LICENSE).
