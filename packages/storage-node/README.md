# @openlfcp/storage-node

Durable Node.js storage for LFCP clients (LFCP-035):

- `SqliteLfcpStorage`, the `LfcpStorage` interface of `@openlfcp/storage` on
  SQLite through [better-sqlite3](https://github.com/WiseLibs/better-sqlite3)
  13.0.3;
- `FileSecretStore`, a `SecretStore` in a local directory.

**This package is Node only.** It is meant for headless Node clients, the CLI,
the examples and tests. It is the only sdk-ts package allowed to use `node:*`
modules (`scripts/check-boundaries.mjs`), and no portable package may depend
on it. The Obsidian plugin does not use it: Obsidian has its own adapter
(LFCP-059), which runs the same contract suite (`runStorageContract` from
`@openlfcp/storage/contract`).

## Scope

Part of the OpenLFCP TypeScript SDK, which implements the OpenLFCP MVP 0.1
subset of [LFCP-WIRE-01](https://github.com/openlfcp/spec/blob/main/wire/LFCP-WIRE-01.md)
at `mvp-0.1-baseline.8`, not every deferred WIRE-01 feature. It does not
claim full LFCP-WIRE-01 conformance. This is the MVP 0.1 release
(`0.1.1`, npm dist-tag `latest`). Until 1.0, minor versions may change APIs.

## SQLite

```ts
const storage = SqliteLfcpStorage.open("/path/to/lfcp.sqlite");
// ... storage.commit([...]), storage.dataUnits.get(id), ...
storage.close();
```

- **Durability.** WAL journal with `synchronous=FULL`: a transaction is on disk
  when it commits, and every promise resolves after its transaction committed.
  These are SQLite's guarantees on a local filesystem whose `fsync` works,
  nothing more.
- **Atomicity.** One `commit()` is one `BEGIN IMMEDIATE` transaction: every
  write or none, with the Control Head compare-and-set checked inside it.
- **Sequences.** Actor and Snapshot sequence reservations read and advance
  their counter inside one `BEGIN IMMEDIATE` transaction, which holds the write
  lock across processes. No two callers ever get the same value, in this
  process or another. A crash after a reservation committed skips that value;
  it never reuses it.
- **Exact bytes.** Control Records, Data Units, Key Packages and Snapshots are
  stored as their exact bytes; the other columns are indexes. Storing an ID
  again with other bytes fails the whole batch. Bytes are copied out, so callers
  never share SQLite's buffers.
- **Indexes.** Data Units are indexed by `(resource, actor, sequence)`, which
  serves equivocation checks, held-unit retries and anti-entropy ranges, and by
  `(resource, status)`.
- **Schema.** A `schema_version` table and ordered migrations, from version 1.
  A database from a newer schema is refused, never downgraded.
- uint64 values (sequences, epochs, route versions) are stored as 20-digit
  zero-padded text, so they sort numerically and never overflow SQLite's
  signed 64-bit integers.

The driver ships prebuilt Node-API binaries for macOS, Linux (glibc and musl)
and Windows on x64 and arm64. Installing needs no compiler and no install
script, and the same binary loads in Electron's main process.

## Secrets

```ts
const secrets = new FileSecretStore("/path/to/secrets");
await secrets.put(dekSecretRef(resource, epoch), dekBytes);
```

> **MVP limitation: secrets are stored in plaintext on disk.** They are
> protected only by file permissions: the directory is `0700` and every file
> `0600`, owned by the user running the client. Anyone who can read those files
> as that user, as root, or from a backup has the keys. OS keychain integration
> or passphrase-based encryption is a follow-up.

- One file per `SecretRef`, named by the hex of the reference (references are
  public names, never secret material).
- Writes go to a temporary file that is fsynced, renamed over the target and
  followed by a directory fsync. A crash leaves the old value or the new one,
  never a torn file.
- There is no list operation, and the store prints as `[FileSecretStore]`, so
  values cannot leak into logs.
- Write a secret before committing the row that references it (see
  `@openlfcp/storage`).

## Tests

`test/contract.test.ts` runs the shared storage contract, including a reopen,
against SQLite and the file store. `test/crash.test.ts` kills a writing child
process with `SIGKILL` and checks the reopened database: no sequence reuse, no
torn batch, every committed batch present. Every test uses its own temporary
directory and deletes it.

## Links

- Specification: [openlfcp/spec](https://github.com/openlfcp/spec)
- Source and the other SDK packages: [openlfcp/sdk-ts](https://github.com/openlfcp/sdk-ts)
- Issues: [openlfcp/sdk-ts/issues](https://github.com/openlfcp/sdk-ts/issues)

## License

Apache-2.0. See [LICENSE](LICENSE).
