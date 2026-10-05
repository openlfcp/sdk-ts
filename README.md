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
compare-and-swap (LFCP-022) and Data Epoch rotation with the strict
cutoff (LFCP-023), and
`@openlfcp/storage` the actor sequence reservation contract (LFCP-018),
and `@openlfcp/shared-objects` the Shared Task model and profile
validation over logical state (LFCP-030). `@openlfcp/client` still
exports only a `PACKAGE` placeholder. Protocol code arrives with the backlog tasks that
own each package. The official vectors run through the conformance runner
(LFCP-017; see [Conformance](#conformance)).

## Packages

| Package | Purpose | Depends on | Exports |
| --- | --- | --- | --- |
| `@openlfcp/core` | Identifiers, shared types, errors, byte helpers | none | `generateResourceId`; 32-byte ids (`ResourceId`, `PrincipalId`, `Hash32`, `ControlRecordId`, `DataUnitId`), `ObjectId` (UUIDv7), uint64 `DataEpoch`/`ActorSequence` and `uint64BE`, hex/base64url, `LfcpError` |
| `@openlfcp/crypto` | Thin wrapper over the audited `@noble` libraries | core | `sha256`; `SigningKeyPair` (Ed25519) and `AgreementKeyPair` (X25519) with redacted diagnostics; `generate*KeyPair`, `import*Key`, `exportSecretKeyBytes`, `verifyEd25519`; HKDF-SHA256 (`hkdfExtract`, `hkdfExpand`); Data Epoch keys (`ResourceDEK`, `generateResourceDEK`, `importResourceDEK`, `dekCommitment`, `ActorDataKey`/`deriveActorDataKey`, `SnapshotKey`/`deriveSnapshotKey`, `dataUnitNonce`, `snapshotNonce`) |
| `@openlfcp/wire` | Deterministic CBOR, COSE, LFCP Wire structures and codecs | core, crypto | Principal Descriptor (`principalDescriptor*`, `encode/decodePrincipalDescriptor`, `derivePrincipalId`); canonical COSE_Sign1 (`signObject`, `parseSignedObject`, `verifySignedObject`, `sigStructureBytes`, `objectId`); typed payloads (`parseControlRecord`, `parseDataUnit`, `parseKeyPackage`, `parseSnapshot`, `decode*Payload`, `*PayloadFromCbor`, `expectedSignerOf`, `actorHaveFromCbor`/`actorHaveToCbor`, `canonicalFrontierFromCbor`/`canonicalFrontierToCbor`, `endpointFromCbor`/`endpointToCbor`, `checkWriterUrl`, `ENDPOINT_FLAGS`, `CONTROL_TYPE`); typed Control Records (`decodeControlRecord`, `signControlRecord`, `encodeControlRecordPayload`, `controlBodyFromCbor`/`controlBodyToCbor`, `isMvpSupported`, `controlRecordSigner`, `verifyGenesis`, ownership-transfer offer/accept parsers); Control Chain validation (`validateControlChain` → linear `ControlState` with `stateAt(head)` / `CONTROL_CONFLICT` / invalid, authority enforced); capabilities (`ABILITY`, `ABILITY_NAMES`, `hasAbility`, `abilitiesOf`, `authorizeControlRecord`, `canDistributeKey`, `verifyOwnerTransfer`); Control transitions (`proposeControlTransition`, `proposeControlPut`, `decodeControlPutBody`: accepted / already-committed / CONTROL_HEAD_MISMATCH / refused, pure, no durable CAS); Data Epochs (`rotateEpoch`, `classifyDataUnit` → accept / quarantine `STALE_DATA_EPOCH` / reject, `serverAcceptsDataPut`, `isSequenceWithinFrontier`, `KEY_EPOCH_REASON`); low-level deterministic CBOR (`encode`, `decodeStrict`, `decodeDeterministic`, `isDeterministic`, `cborMap`) under the `@openlfcp/wire/cbor` subpath |
| `@openlfcp/storage` | Storage interfaces only (adapters such as a future `@openlfcp/storage-node` live elsewhere) | core | `ActorSequenceReservation` (durable-before-use contract; durable implementations are LFCP-034 to LFCP-036), `nextActorSequence`, `SequenceReuseGuard`, and `InMemoryActorSequenceReservation` for tests and development only (not crash-safe) |
| `@openlfcp/shared-objects` | SHARED-OBJECTS-PROFILE-01 (`org.openlfcp.shared-objects.v1`) | core, crypto | Task over logical state (`Task`, `parseTask`, `createTask`, intent mutators `setTitle`, `setStatus`, `complete`, `reopen`, `cancel`, `setDue`/`clearDue`, `setScheduled`/`clearScheduled`, `setPriority`, `addTag`/`removeTag`, `assign`/`unassign`, `deleteTask`/`restoreTask`); profile validation (`validateRoot`, `objectProblems`, `validateTransition`: `PROFILE_INVALID` with §74.1 diagnostics); `principalRef`, `deriveActorId`, `frameProfilePayload`/`unframeProfilePayload`, Local Date and timestamp checks. The Automerge binding is LFCP-031 |
| `@openlfcp/client` | Session, Control Plane and Data Plane synchronization | core, wire, storage, crypto | `PACKAGE` |

```text
core ◀── crypto ◀── wire ◀──────────┐
  ▲ ▲       ▲                       │
  │ │       └──── shared-objects    client  (also → core, storage, crypto)
  │ └──── storage ◀─────────────────┘
  └──── (every package)
```

Allowed edges: crypto → core; wire → core, crypto; storage → core;
shared-objects → core, crypto; client → core, wire, storage, crypto.
Nothing depends on `client`. Future profiles get their own package next to
`shared-objects`.

`pnpm lint` enforces these edges with `scripts/check-boundaries.mjs`. It
fails on:

- an edge outside the graph;
- any `obsidian` dependency or import;
- any `@noble/*` dependency or import outside `@openlfcp/crypto`;
- any `node:` or Node built-in import or Node-only global (`process`,
  `Buffer`, …) in these packages.

Its self-tests live in `scripts/boundary-fixtures/`.

Runtime dependencies are deliberately few. Only `@openlfcp/crypto` has
external ones: `@noble/hashes` and `@noble/curves`. They are audited, pure
JavaScript and run unchanged in Node.js, browsers and Obsidian.

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
{ "tag": "mvp-0.1-baseline.2", "commit": "1527feda3f4cc3accb62b3fe0ea3ab2e0d40c0f6" }
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
