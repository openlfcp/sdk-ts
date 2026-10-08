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

## Scope

Part of the OpenLFCP TypeScript SDK, which implements the OpenLFCP MVP 0.1
subset of [LFCP-WIRE-01](https://github.com/openlfcp/spec/blob/main/wire/LFCP-WIRE-01.md)
at `mvp-0.1-baseline.9`, not every deferred WIRE-01 feature. It does not
claim full LFCP-WIRE-01 conformance. This is the MVP 0.1 release
(`0.1.3`, npm dist-tag `latest`). Until 1.0, minor versions may change APIs.

## Shared sections (Working Draft)

`@openlfcp/shared-objects/sections` implements part of
SHARED-SECTIONS-PROFILE-01 (`org.openlfcp.shared-sections.v1`, Working
Draft 0.3, not in any implementation baseline): profile dispatch by a
Resource's Genesis profile (`profileModel`), the section actor binding
(`deriveSectionActorId`) and schema validation of a section document
(`validateSection`, `SectionDocument`), and the writer of a section's
creation and Task intents (`SectionReplica`). Moves, lifecycle, Text
edits, the effective tree and the section admission rules are not there
yet. It may change
without notice until the profile is in a baseline.

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
With the slim build it must `await initializeAutomerge()` (exported here: it
imports the base64 wasm dynamically, decodes it in a few milliseconds where
Automerge's own helper takes about 200 ms, and compiles it asynchronously) before
first using this package; on every other build that call is a no-op. It is
idempotent and safe to call concurrently (one shared in-flight promise; a
failure clears it, so a later call retries). Calling any other export
before it resolves on the slim build is not guarded: the host awaits it
first (the Obsidian plugin does so in its startup, before any replica
exists). The
Obsidian plugin uses the slim build this way (LFCP-059): Chromium refuses to
compile more than 4 KB of wasm synchronously on a renderer's main thread,
which the base64 build would do.

## Rules decided in baseline.4

These followed the reference corpus generator as provisional rules and are
normative since `mvp-0.1-baseline.4` (ADR 0003). The source cites them by
section and decision ID:

- **G-SC3** (§30): every profile string is an Automerge scalar string
  (`ImmutableString`), never collaborative Text. A known field stored as Text
  is `PROFILE_INVALID` / `INVALID_FIELD_TYPE`.
- **G-SC4** (§58): an intent that writes a value already present deletes it
  first, so it is a real concurrent write: a re-add wins over a concurrent
  removal, and a restore conflicts with a concurrent delete. Because of that delete+put, Automerge's property order differs
  between the writer and receivers, so `root()` returns keys in canonical
  (code-unit) order at every level: `JSON.stringify(root())` is comparable
  across replicas holding the same state.
- **G-EP7** (§14.1): replica state is a deterministic function of the set of
  accepted changes (`fromChanges`, `rebuildWithout`).
- **SO-SEC1** (§8, §11): a Data Unit carries only changes of its signer's §8
  actor; any other is `PROFILE_INVALID` / `CHANGE_ACTOR_MISMATCH`.
- **SOG-2** (§74.1): one diagnostic per field value, the first in the table's
  order, with `IMMUTABLE_FIELD_MUTATED` last (`firstPerField`).

## Links

- Specification: [openlfcp/spec](https://github.com/openlfcp/spec)
- Source and the other SDK packages: [openlfcp/sdk-ts](https://github.com/openlfcp/sdk-ts)
- Issues: [openlfcp/sdk-ts/issues](https://github.com/openlfcp/sdk-ts/issues)

## License

Apache-2.0. See [LICENSE](LICENSE).
