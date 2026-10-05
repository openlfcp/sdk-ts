# @openlfcp/shared-objects

The TypeScript implementation of
[SHARED-OBJECTS-PROFILE-01](https://github.com/openlfcp/spec/blob/main/profiles/SHARED-OBJECTS-PROFILE-01.md)
(`org.openlfcp.shared-objects.v1`):

- the Task model, intent mutators and profile validation over logical state
  (LFCP-030);
- the Automerge binding `SharedObjectsReplica` (LFCP-031): one semantic intent
  is one Automerge change written by the §8 actor, scalar conflicts stay
  visible, tags and assignees are add-wins sets, deletion is a tombstone, and
  unknown data survives every write;
- the §11 Data Unit and §13 Snapshot plaintext framing, with checks that the
  framed bytes are one valid Automerge change or a full save.

LFCP verification, decryption and authorization happen before a change
reaches the replica (§95). The replica has no Markdown or editor concepts.

## Automerge and WebAssembly

The package depends on `@automerge/automerge` **3.5.0**, pinned exactly,
which is the profile's Automerge compatibility target. No other sdk-ts
package may use Automerge (`scripts/check-boundaries.mjs`).

Automerge is Rust compiled to WebAssembly. This package imports the plain
`@automerge/automerge` specifier and stays synchronous: Automerge's
conditional exports choose how each runtime loads the wasm, and the
host's bundler handles the rest.

| Runtime | Export condition | How the wasm loads |
| --- | --- | --- |
| Node.js (tests, CLI, Electron main) | `node` | Read from the package with `fs` at import time, synchronously |
| Bundlers with ESM wasm support (Vite with `vite-plugin-wasm`, webpack 5 `asyncWebAssembly`) | `browser` | Imported as a `.wasm` module by the bundler |
| webpack without wasm configuration | `webpack` | Inlined as base64 and instantiated synchronously |
| Cloudflare Workers | `workerd` | Imported as a wasm module |
| Anything else (plain ESM) | `import` | Inlined as base64 (about 4.6 MB of JavaScript), instantiated synchronously |

A host whose bundler cannot import `.wasm` files can resolve the base64
build instead, or alias `@automerge/automerge` to `@automerge/automerge/slim`.
With the slim build it must `await initializeBase64Wasm(...)` or
`initializeWasm(...)` from that entry before first using this package. The
Obsidian plugin's choice belongs to the Obsidian tasks. This package does
not choose a build at run time.

## Provisional rules

These follow the reference corpus generator and are marked
`// PROVISIONAL (<id>)` in the source until the project owner decides them:

- **G-SC3**: every profile string is an Automerge scalar string
  (`ImmutableString`), never collaborative Text. A known field stored as Text
  is `PROFILE_INVALID` / `INVALID_FIELD_TYPE`.
- **G-SC4**: an intent that writes a value already present deletes it first,
  so it is a real concurrent write: a re-add wins over a concurrent removal,
  and a restore conflicts with a concurrent delete.
- **G-EP7**: replica state is a deterministic function of the set of accepted
  changes (`fromChanges`, `rebuildWithout`).
