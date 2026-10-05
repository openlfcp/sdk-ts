# openlfcp/sdk-ts

Reusable TypeScript implementation of LFCP.

The SDK does not depend on Obsidian or any other editor. Its packages must
stay portable to browsers and editors; Node-only code goes into separate
`*-node` packages.

## Status

Workspace scaffold (LFCP-011). `@openlfcp/core` has its identifier
primitives (LFCP-012), `@openlfcp/crypto` the Principal key material and
`@openlfcp/wire` its deterministic CBOR codec (LFCP-013) and the Principal
Descriptor (LFCP-014); the other packages still export only a `PACKAGE`
placeholder. Protocol code arrives with the backlog tasks that own each
package.

## Packages

| Package | Purpose | Depends on | Exports |
| --- | --- | --- | --- |
| `@openlfcp/core` | Identifiers, shared types, errors, byte helpers | none | 32-byte ids (`ResourceId`, `PrincipalId`, `Hash32`, `ControlRecordId`, `DataUnitId`), `ObjectId` (UUIDv7), hex/base64url, `LfcpError` |
| `@openlfcp/crypto` | Thin wrapper over the audited `@noble` libraries | core | `sha256`; `SigningKeyPair` (Ed25519) and `AgreementKeyPair` (X25519) with redacted diagnostics; `generate*KeyPair`, `import*Key`, `exportSecretKeyBytes`, `verifyEd25519` |
| `@openlfcp/wire` | Deterministic CBOR, COSE, LFCP Wire structures and codecs | core, crypto | Principal Descriptor (`principalDescriptor*`, `encode/decodePrincipalDescriptor`, `derivePrincipalId`); low-level deterministic CBOR (`encode`, `decodeStrict`, `isDeterministic`, `cborMap`) under the `@openlfcp/wire/cbor` subpath |
| `@openlfcp/storage` | Storage interfaces only (adapters such as a future `@openlfcp/storage-node` live elsewhere) | core | `PACKAGE` |
| `@openlfcp/shared-objects` | SHARED-OBJECTS-PROFILE-01 (`org.openlfcp.shared-objects.v1`) | core, crypto | `PACKAGE` |
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
pnpm test     # vitest
```

`pnpm typecheck` also type-checks the tests. `pnpm format` applies Biome
formatting.

Requires Node.js 24 or later and pnpm 10.

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
