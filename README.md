# openlfcp/sdk-ts

Reusable TypeScript implementation of LFCP.

The SDK does not depend on Obsidian or any other editor. Its packages must
stay portable to browsers and editors; Node-only code goes into separate
`*-node` packages.

## Status

Workspace scaffold (LFCP-011). `@openlfcp/core` has its identifier
primitives (LFCP-012, random Resource IDs LFCP-019) and uint64 epoch and
sequence types (LFCP-018),
`@openlfcp/crypto` the Principal key material (LFCP-014) and the Data
Epoch keys (LFCP-018), `@openlfcp/wire` its deterministic CBOR codec
(LFCP-013), the Principal Descriptor (LFCP-014), canonical COSE_Sign1
(LFCP-015), the typed signed-object payloads (LFCP-016) and the typed
Control Record codec with Genesis (LFCP-019), Control Chain validation
with the Control state (LFCP-020), the capability engine with
ownership transfer verification (LFCP-021), Control transitions with
compare-and-swap (LFCP-022), Data Epoch rotation with the strict
cutoff (LFCP-023), HPKE Key Packages (LFCP-024) and the encrypted,
signed Data Unit with its receive pipeline (LFCP-025), the message
codec (LFCP-026) and the session handshake with the §63/§64 state
machines (LFCP-027), and Have Vector anti-entropy with Control sync
planning (LFCP-028), the encrypted signed Snapshot (LFCP-029), the
invitation URI and invitation-secret codec (LFCP-039b),
`@openlfcp/storage` the actor sequence reservation contract (LFCP-018),
and `@openlfcp/shared-objects` the Shared Task model and profile
validation over logical state (LFCP-030) with its Automerge binding
(LFCP-031), and `@openlfcp/client` Data
Unit creation (LFCP-025), the WebSocket sync session (LFCP-039a), link
invitations with the one-time claim (LFCP-053) and restart recovery
(LFCP-038), and `@openlfcp/storage-idb` durable IndexedDB storage for
browsers and Obsidian (LFCP-059). Protocol code arrives with the backlog tasks that
own each package. The official vectors run through the conformance runner
(LFCP-017; see [Conformance](#conformance)).

## Packages

| Package | Purpose | Depends on | Exports |
| --- | --- | --- | --- |
| `@openlfcp/core` | Identifiers, shared types, errors, byte helpers | none | `generateResourceId`; 32-byte ids (`ResourceId`, `PrincipalId`, `Hash32`, `ControlRecordId`, `DataUnitId`), `ObjectId` (UUIDv7), uint64 `DataEpoch`/`ActorSequence` and `uint64BE`, hex/base64url, `LfcpError` |
| `@openlfcp/crypto` | Thin wrapper over the audited `@noble` libraries | core | `sha256`; `SigningKeyPair` (Ed25519) and `AgreementKeyPair` (X25519) with redacted diagnostics; `InvitationSecret` (the Invitation Principal's two key pairs, §18.2, redacted); `generate*KeyPair`, `import*Key`, `exportSecretKeyBytes`, `verifyEd25519` (strict, §10.5.1), `isValidEd25519PublicKey`; HKDF-SHA256 (`hkdfExtract`, `hkdfExpand`); Data Epoch keys (`ResourceDEK`, `generateResourceDEK`, `importResourceDEK`, `dekCommitment`, `ActorDataKey`/`deriveActorDataKey`, `SnapshotKey`/`deriveSnapshotKey`, `dataUnitNonce`, `snapshotNonce`); ChaCha20-Poly1305 for Data Units (`encryptDataUnit`, `decryptDataUnit`, keyed by `ActorDataKey`, sequence nonce) and Snapshots (`encryptSnapshot`, `decryptSnapshot`, keyed by `SnapshotKey`); RFC 9180 HPKE (`sealDek`, `openDek`: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, Base mode) |
| `@openlfcp/wire` | Deterministic CBOR, COSE, LFCP Wire structures and codecs | core, crypto | Principal Descriptor (`principalDescriptor*`, `encode/decodePrincipalDescriptor`, `derivePrincipalId`); canonical COSE_Sign1 (`signObject`, `parseSignedObject`, `verifySignedObject`, `sigStructureBytes`, `objectId`); typed payloads (`parseControlRecord`, `parseDataUnit`, `parseKeyPackage`, `parseSnapshot`, `decode*Payload`, `*PayloadFromCbor`, `expectedSignerOf`, `actorHaveFromCbor`/`actorHaveToCbor`, `canonicalFrontierFromCbor`/`canonicalFrontierToCbor`, `endpointFromCbor`/`endpointToCbor`, `checkWriterUrl`, `checkReceivedUrl`, `ENDPOINT_FLAGS`, `CONTROL_TYPE`); typed Control Records (`decodeControlRecord`, `signControlRecord`, `encodeControlRecordPayload`, `controlBodyFromCbor`/`controlBodyToCbor`, `isMvpSupported`, `controlRecordSigner`, `verifyGenesis`, ownership-transfer offer/accept parsers); Control Chain validation (`validateControlChain` → linear `ControlState` with `stateAt(head)` / `CONTROL_CONFLICT` / invalid, authority enforced); capabilities (`ABILITY`, `ABILITY_NAMES`, `hasAbility`, `abilitiesOf`, `authorizeControlRecord`, `canDistributeKey`, `verifyOwnerTransfer`); Control transitions (`proposeControlTransition`, `proposeControlPut`, `decodeControlPutBody`: accepted / already-committed / CONTROL_HEAD_MISMATCH / refused, pure, no durable CAS); Data Epochs (`rotateEpoch`, `classifyDataUnit` → accept / quarantine `STALE_DATA_EPOCH` / reject, `serverAcceptsDataPut`, `isSequenceWithinFrontier`, `KEY_EPOCH_REASON`); Key Packages (`sealKeyPackage`, `openKeyPackage`, `receiveKeyPackage`, `verifyKeyPackage`, `keyPackageHpkeInfo`, `keyPackageHpkeAad`); invitations §18.2 (`encodeInviteSecret`/`decodeInviteSecret`, `invitationPrincipal`, `verifyInvitationSecret` against the grant's subject, `assembleInviteUri`/`parseInviteUri` for the targeted and bearer `lfcp://join` forms, `INVALID_INVITATION`); Data Units (`dataUnitAad`, `encodeDataUnitPayload`, `sealDataUnit`, `checkDataUnit` for the DEK-free server checks, `receiveDataUnit` → accepted / duplicate / equivocation / held / quarantined / rejected / local-failure, the `DataProfileCodec` hook, the `SeenUnits` contract with the test-only `InMemorySeenUnits`); messages (`MESSAGE_TYPE`, `ERROR_CODE`, typed bodies `MessageBodies`, `decodeMessage` / `encodeMessage`, `decodeEnvelope`, `decodeFrame` for binary/text frames with `closesConnection`, `messageErrorWireCode`, `newMessageId`, `createMessage`, `replyTo`, `DEFAULT_MAX_MESSAGE_BYTES`; no sockets); the session handshake (`WIRE_PROFILE`, `authTranscript`, `signAuthProof`, `verifyAuthProof`, `selectWireProfile`, pure `startServerSession`/`serverReceive` and `startClientHandshake`/`clientReceive` steps, `AuthenticatedSession` with an opaque hosting credential and no abilities; `clientConnectionTransition` §63 and `serverSessionTransition` §64); Have Vectors (`HaveVector`, `normalizeLiveHaves` lossless with G-HV1 checks applied by `decodeMessage`, `addSequence`/`addRange`, `hasSequence`, `missingFrom`, `missingAfter`, `unionHaves`, `batchDataRanges` at `MAX_DATA_GET_RANGES` = 256, `liveHavesOf`); Control sync planning (`planControlSync` → in-sync / peer-empty / fetch / peer-behind / fork, `localControlOf`); Snapshots (`snapshotAad`, `encodeSnapshotPayload`, `sealSnapshot`, `checkSnapshot` for the DEK-free checks, `receiveSnapshot` → accepted / rejected / local-failure, `beyondCutoff` for §29 G-EP4); low-level deterministic CBOR (`encode`, `decodeStrict`, `decodeDeterministic`, `isDeterministic`, `cborMap`) under the `@openlfcp/wire/cbor` subpath |
| `@openlfcp/storage` | Storage interfaces only (adapters such as `@openlfcp/storage-node` live elsewhere) | core | `LfcpStorage` (LFCP-034): readers for Control Records, head, conflict and epochs (`control`), Data Units with status, accepted mark and the equivocation and range lookups (`dataUnits`, `recordSeen`), Key Packages, Snapshots, Resources and routes, the outbound queue and Data Profile checkpoints, per-Resource sync state (recently ACKed IDs, ACK durability), outbound retry state (next attempt, blocked reason), and one atomic `commit` of `StorageWrite`s with a Control Head compare-and-set (exact signed bytes are authoritative and copied in and out); `SecretStore` with `SecretRef`s (`secretRef`, `dekSecretRef`, `principalKeySecretRef`; no enumeration) and the test-only `InMemoryLfcpStorage` and `InMemorySecretStore`; the reusable contract suite `runStorageContract` (`@openlfcp/storage/contract`) that every adapter runs; `ActorSequenceReservation` (durable-before-use contract; durable implementations are LFCP-034 to LFCP-036), `nextActorSequence`, `SequenceReuseGuard`, and `InMemoryActorSequenceReservation` for tests and development only (not crash-safe); `SnapshotSequenceReservation` (per resource, epoch and publisher, the same contract), the test-only `InMemorySnapshotSequenceReservation` and `SnapshotSequenceGuard`; reservations fail closed with `SEQUENCE_REUSE` when a counter is behind a stored unit or Snapshot (LFCP-038); the `delete-snapshot` write |
| `@openlfcp/shared-objects` | SHARED-OBJECTS-PROFILE-01 (`org.openlfcp.shared-objects.v1`) | core, crypto | Task over logical state (`Task`, `parseTask`, `createTask`, intent mutators `setTitle`, `setStatus`, `complete`, `reopen`, `cancel`, `setDue`/`clearDue`, `setScheduled`/`clearScheduled`, `setPriority`, `addTag`/`removeTag`, `assign`/`unassign`, `deleteTask`/`restoreTask`); profile validation (`validateRoot`, `objectProblems`, `validateTransition`: `PROFILE_INVALID` with §74.1 diagnostics); `principalRef`, `deriveActorId`, `frameProfilePayload`/`unframeProfilePayload`, Local Date and timestamp checks; the Automerge binding `SharedObjectsReplica` (`create`, `empty`, `fromSave`, `fromSnapshot`, `fromChanges`, `rebuildWithout`; `apply` one intent → one change with its §11 plaintext, `receive`/`receiveChange` → applied / duplicate / missing_dependencies, `task` views with `ScalarView` conflicts, `conflicts`, `collisions`, `validate`, `save`, `snapshot`, change notifications), `resolveFieldConflict`, `ObjectIdCollisionError`, and the §11/§13 byte checks `checkChange`, `frameChange`/`unframeChange`, `frameSnapshot`/`unframeSnapshot`; `SharedObjectsDataProfile`, the Data Profile handler for `DataUnitApplier` (signer-bound codec, buffered Automerge dependencies, object isolation diagnostics, G-EP7 `exclude`, `onObjectChanged`, `checkpoint`/`restore` of the replica, its unit refs and its §9 sequence, `recordLocal` for own units, `snapshotCodec`/`loadSnapshot`/`snapshotState`, `has`/`reset`); `initializeAutomerge` for hosts on Automerge's `/slim` build (LFCP-059) |
| `@openlfcp/storage-node` | Durable Node.js storage (Node only: headless Node, CLI, examples, tests; Obsidian uses `storage-idb`) | core, storage | `SqliteLfcpStorage` (better-sqlite3 13.0.3; WAL, `synchronous=FULL`, one `BEGIN IMMEDIATE` transaction per commit and per sequence reservation, schema migrations), `FileSecretStore` (0600 files in a 0700 directory, atomic writes; MVP: plaintext on disk) |
| `@openlfcp/storage-idb` | Durable portable storage on IndexedDB (browsers, Electron/Obsidian, mobile WebViews) | core, storage | `IdbLfcpStorage` (LFCP-059): `LfcpStorage` with one strict-durability readwrite transaction per commit (Control Head compare-and-set inside it), sequence reservations that fail closed against stored objects and call `onReserved` before returning (to mirror a high-water mark), `counters()`, and a small `meta` store for application markers; passes `runStorageContract` |
| `@openlfcp/client` | Session, Control Plane and Data Plane synchronization | core, wire, storage, crypto | `createDataUnit` (sequence from an `ActorSequenceReservation` only; checks head, profile, data/write and DEK before reserving); `DataUnitApplier` (received units through `receiveDataUnit`, then the Resource's `DataProfileHandler`: applied / profile-pending / duplicate / equivocation / held, retried when the gap closes / quarantined / rejected / local-failure / profile-rejected / `PROFILE_UNSUPPORTED`; `reconcileEpochs` excludes merged units a new Key Epoch puts beyond its cutoff, §19.1 G-EP7; no unit of an equivocating set stays merged, §26.2 G-DP5), on `LfcpStorage`; storage glue: `StoredSeenUnits` (the wire `SeenUnits`, durable, with un-accept), `loadControlChain`/`saveControlChain`/`saveControlConflict`, `dekResolver` (DEKs only through the `SecretStore`), `createQueuedDataUnit` (the unit and its outbound entry in one commit), `dataUnitRow`; the pending outbound queue (LFCP-036): `OutboundQueue` (same exact bytes in a new message per attempt, §88 order, attempts stored before sending, ACK by object ID with durability up to READY's level, per-NACK-code handling with blocking, §88 step 7 `reconcileEpochs`, `connectionLost`, `controlSynced`, `discard`; time and retries through the caller's `RetryPolicy`, `exponentialBackoff`), `resourceSyncState` (Have-based), `queueKeyPackage`, `queueSnapshot`, `createQueuedSnapshot`, `queueControlRecord`, `outboundItem`, and `ProfileCheckpointer` (caller-driven debounced checkpoints); `DataUnitApplier.acceptCovered` for units a loaded Snapshot covers, `snapshotFrontier`; `createQueuedDataUnit` with `onCreated` and a function `also`, so a profile records its own units in the same commit; `createSnapshot` (sequence from a `SnapshotSequenceReservation` only; canonical frontier; checks head, profile, snapshot/publish, DEK and G-EP4 before reserving); the sync session (LFCP-039a): `SyncClient` (one LFCP session over WebSocket driving the §65 machine of every opened Resource: Control, Keys, Data catch-up, then LIVE with pushes, periodic DATA_HAVE and the outbound queue; both `reconcileEpochs` on every new Control state; connection loss closes every Resource, `ReconnectPolicy`; `tick(now)` on the caller's clock, `startSyncDriver`; `host`, `open`, `close`, `flush`, events; Snapshot catch-up through a `SnapshotBinding`, then only the units beyond its frontier, and `publishSnapshot` with an optional `snapshotPolicy`), `LfcpConnection` (lfcp-1, binary frames, size limits, handshake, §63, heartbeat), `platformWebSocket`, `resourcePhaseTransition` (§65); link invitations (§18, §73): `createInvitation` (Invitation Principal, grant with an explicit claim_limit, its Key Package, queued; the redacted `InvitationLink`) and `acceptInvitation` (as the Invitation Principal: chain, §18.2 subject check, invitation Key Package, `CAPABILITY_CLAIM` by CONTROL_PUT with one refresh after CONTROL_HEAD_MISMATCH → claimed / refused / unavailable, then the claimant's storage holds the chain and the DEK); restart recovery (LFCP-038): `DataUnitApplier.replayStored` (accepted units the restored profile state lacks, applied again from their stored bytes; `SyncClient` runs it before each data round and reports `replayed`), the profile handler's optional `has`/`reset`, local corruption failing closed (`loadControlChain` → `INVALID_CONTROL_CHAIN`, outbound bytes that do not hash to their ID are blocked), and, PROVISIONAL (SNAP-EP), `reconcileEpochs` dropping a loaded Snapshot that a later Key Epoch cuts into and rebuilding from accepted units only |

```text
core ◀── crypto ◀── wire ◀──────────┐
  ▲ ▲       ▲                       │
  │ │       └──── shared-objects    client  (also → core, storage, crypto)
  │ └──── storage ◀─────────────────┘
  └──── (every package)
```

Allowed edges: crypto → core; wire → core, crypto; storage → core;
shared-objects → core, crypto; client → core, wire, storage, crypto;
storage-node → core, storage; storage-idb → core, storage. Nothing depends on `client`, and no portable
package depends on the Node-only `storage-node`. Future profiles get their own package next to
`shared-objects`.

`pnpm lint` enforces these edges with `scripts/check-boundaries.mjs`. It
fails on:

- an edge outside the graph;
- any `obsidian` dependency or import;
- any `@noble/*` dependency or import outside `@openlfcp/crypto`;
- any `@automerge/*` dependency or import outside `@openlfcp/shared-objects`;
- any `node:` or Node built-in import or Node-only global (`process`,
  `Buffer`, …) in the portable packages (every package except the Node-only
  `storage-node`);
- a portable package that depends on or imports a Node-only package.

Its self-tests live in `scripts/boundary-fixtures/`.

Runtime dependencies are deliberately few. `@openlfcp/crypto` has
`@noble/hashes` and `@noble/curves`, and for HPKE `hpke` with
`@panva/hpke-noble`, which runs the same noble packages (one copy each). They are audited, pure
JavaScript and run unchanged in Node.js, browsers and Obsidian.
`@openlfcp/shared-objects` has `@automerge/automerge`, pinned at 3.5.0, the
profile's compatibility target. It ships WebAssembly, which each runtime
loads through the package's conditional exports; see
[its README](packages/shared-objects/README.md).
The Node-only `@openlfcp/storage-node` has `better-sqlite3`, pinned at 13.0.3,
which ships prebuilt Node-API binaries; see
[its README](packages/storage-node/README.md).
`@openlfcp/storage-idb` has no runtime dependency beyond the SDK; its tests use
`fake-indexeddb` 6.2.5 (pinned, a devDependency); see
[its README](packages/storage-idb/README.md).

Each package is ESM-only and publish-ready in shape:

- an `exports` map with `types` and `import` conditions;
- `files: ["dist"]`, `sideEffects: false`;
- `publishConfig.access: public`, version `0.0.0`.

## Build from a clean checkout

```sh
pnpm install --frozen-lockfile
pnpm build    # tsc -b: strict, project references, dist/ with .d.ts and sourcemaps
pnpm lint     # Biome, then the boundary check and its self-tests
pnpm test     # vitest, including the conformance run
```

`pnpm typecheck` also type-checks the tests. `pnpm format` applies Biome
formatting.

Requires Node.js 24 or later and pnpm 10, and a checkout of
`openlfcp/spec` with its tags next to this repository (see below).

## Conformance

The official vectors belong to `openlfcp/spec` and are never copied into
sdk-ts. `spec.lock` pins the spec version the SDK implements:

```json
{ "tag": "mvp-0.1-baseline.6", "commit": "c13aef1245c3f4d433fc2a07635ad92e7552841b" }
```

`conformance/spec.mjs` reads spec files with `git show <commit>:<path>`
from `$LFCP_SPEC_DIR`, or `../spec` by default (a relative value resolves
from the sdk-ts root). It first checks that the tag still resolves to the
locked commit and fails loudly if not. Moving to a new baseline means
changing `spec.lock` deliberately.

```sh
pnpm build
pnpm test:conformance   # only the conformance run and its self-tests
```

`conformance/runner.ts` runs a suite through handlers keyed by
`<type>/<kind>` (`conformance/wire/handlers.ts` for LFCP-TEST-VECTORS-01,
`conformance/shared-objects/handlers.ts` for SHARED-OBJECTS-TEST-VECTORS-01).
Every case must resolve to exactly one of:

- a handler, whose checks must all pass;
- an entry in the suite's `pending.json` naming the task that will
  implement it;
- nothing, which fails the run as an unclassified vector.

A handler may check part of a case and name the parts it cannot check
yet; those parts must be in the pending entry with their task. A pending
entry for something now handled fails as stale, so when a task lands it
removes its entries. Pending cases and parts are reported as todos, never
as passes. The CDDL fixture manifest runs the same way, with
`conformance/wire/cddl-pending.json`, and the Shared Objects contract
fixtures (`profiles/shared-objects-01/schema/fixtures/`) must fail at
exactly the pointers and diagnostics the spec lists.

`conformance/interop/rust-server-sync.test.ts` runs the client against the
Rust reference server over a real WebSocket (LFCP-039a): it builds
`../server` with cargo (or `$LFCP_SERVER_DIR`) into a shared temporary
target directory (`$LFCP_SERVER_TARGET_DIR`), starts it on a temporary
state directory, and is skipped, saying why, when cargo or the checkout
is missing. With `LFCP_REQUIRE_LIVE=1` a missing cargo or checkout fails
the run instead (cargo is often not on the default `PATH`; on macOS add
`~/.rustup/toolchains/stable-aarch64-apple-darwin/bin`).
`rust-server-invite.test.ts` runs the LFCP-053 invitation flow
the same way: invite, claim and sync as the claimant, and every other claim
refused. `rust-server-restart.test.ts` (LFCP-038) runs a client in a child
process on SQLite and a file secret store, kills it mid catch-up and after
writing, restarts it, and checks convergence, no sequence reuse and no
duplicate apply.

`conformance/persistence/` (LFCP-038) kills a writer process at every step
of a local write (before and after reserving, sealing, queueing and
sending) and restarts it on the same SQLite database, and checks what
survives a restart: the Control head, keys, held and quarantined units,
the replica checkpoint with replay and G-EP7, and Snapshot sequences.

The run prints the suite, baseline tag and commit, and writes a summary
to `conformance/.results/` (gitignored). A failure names the vector ID
and check. For bytes it shows the first differing offset and the hex
around it on both sides; for a negative it shows the expected code and
the actual one, or "unexpected success".

## Consuming from sibling repos

During development, `server`, `obsidian` and `examples` use the packages
straight from a local sdk-ts checkout:

```json
{
  "dependencies": {
    "@openlfcp/core": "link:../sdk-ts/packages/core",
    "@openlfcp/client": "link:../sdk-ts/packages/client"
  }
}
```

The `exports` point at `dist/`, so run `pnpm build` in sdk-ts before
building or testing a consumer, and again after changing the SDK.

## Publication

The packages are named `@openlfcp/*` from the start, but they are published
to npm only at milestones, as `0.x` versions under the `next` dist-tag. The
project owner does this. The repository has no publish script or CI publish
job.

## License

Apache License 2.0. See [LICENSE](LICENSE).
