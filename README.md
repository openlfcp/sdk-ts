# openlfcp/sdk-ts

Reusable TypeScript implementation of LFCP.

The SDK does not depend on Obsidian or any other editor. Its packages must
stay portable to browsers and editors; Node-only code goes into separate
`*-node` packages.

## Status

Workspace scaffold (LFCP-011). Every package exports only a `PACKAGE`
placeholder. Protocol code arrives with the backlog tasks that own each
package.

## Packages

| Package | Purpose | Depends on | Exports |
| --- | --- | --- | --- |
| `@openlfcp/core` | Identifiers, shared types, errors, byte helpers | none | `PACKAGE` |
| `@openlfcp/wire` | Deterministic CBOR, COSE, LFCP Wire structures and codecs | core | `PACKAGE` |
| `@openlfcp/storage` | Storage interfaces only (adapters such as a future `@openlfcp/storage-node` live elsewhere) | core | `PACKAGE` |
| `@openlfcp/shared-objects` | SHARED-OBJECTS-PROFILE-01 (`org.openlfcp.shared-objects.v1`) | core | `PACKAGE` |
| `@openlfcp/client` | Session, Control Plane and Data Plane synchronization | core, wire, storage | `PACKAGE` |

```text
core ◀── wire ◀──────┐
  ▲  ◀── storage ◀───┤
  │                  client
  └──── shared-objects
```

Nothing depends on `client`. Future profiles get their own package next to
`shared-objects`.

`pnpm lint` enforces these edges with `scripts/check-boundaries.mjs`. It
fails on an edge outside the graph, any `obsidian` dependency or import, and
any `node:` or Node built-in import or Node-only global (`process`, `Buffer`,
…) in these packages. Its self-tests live in `scripts/boundary-fixtures/`.

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
