# Changelog

All eight `@openlfcp/*` packages are released together, at one version.
Until 1.0, a minor version may change APIs; a patch version does not
remove or rename any.

## Unreleased

### Added

- `@openlfcp/shared-objects/admission` (LFCP-02-085): the admission of
  SHARED-OBJECTS-PROFILE-01 §§7–18 as a module every inheriting profile
  shares (SHARED-SECTIONS-PROFILE-01 §2): the framing, the expansion,
  depth and Snapshot limits, the actor binding with the profile's domain
  (`deriveDomainActorId`, `checkChangeActor`) and the sequence admission
  with held changes (`admitBatch`, `admitChange`). The Shared Objects
  profile now runs on it; its behaviour and exports are unchanged.
- `@openlfcp/shared-objects/sections` (LFCP-02-011), Working Draft:
  SHARED-SECTIONS-PROFILE-01 dispatch by a Resource's Genesis profile
  (`profileModel`, `taskRefModel`; an unknown profile is
  `PROFILE_UNSUPPORTED` and nothing is read or written), the section actor
  binding (`deriveSectionActorId`), and schema validation of a section
  document (`validateSection`, `SectionDocument`): canonical IDs, the
  root and section maps, scalar strings versus Text, references, and one
  §14.2 diagnostic per invalid node, placement or Task. Checked against
  every case of SHARED-SECTIONS-TEST-VECTORS-01 at the development pin in
  `spec-sections.lock`.

## 0.1.3 — 2026-10-08

0.1.2 was published without build output; 0.1.3 is the same code. The
eight 0.1.2 packages on npm hold only `package.json`, `README.md` and
`LICENSE`, and are deprecated. Every change of 0.1.2 below ships in 0.1.3.

0.1.3 is the first release published by CI: the tag `v0.1.3` runs
`.github/workflows/release.yml`, which builds, checks and packs the
packages from a fresh checkout and publishes them with npm Trusted
Publishing (OIDC, with provenance), after an approval in the GitHub
environment `npm-publish`. The dist-tag `next` is no longer moved for a
final release: it names the latest prerelease.

### Added

- `.github/workflows/release.yml`: a pushed tag `vX.Y.Z` publishes the
  eight packages through npm Trusted Publishing; `workflow_dispatch` runs
  the same path as a dry run. A version the registry already has is
  skipped, so a run that failed midway can be run again.
  `scripts/registry-check.mjs` then checks the registry as a user sees it:
  every package's `dist.fileCount`, its dist-tag, and a fresh install that
  imports all eight.

### Fixed

- `pnpm release:check` also packs this checkout as `pnpm publish` would
  (`npm pack --dry-run`) and fails unless it holds the same files as the
  clean build's tarball, `dist/index.js` and `dist/index.d.ts` included. It
  checked only a clean copy before, so a checkout that was never built
  passed it.

## 0.1.2 — 2026-10-08 (broken on npm, deprecated: use 0.1.3)

The 0.1.x sustaining release for MVP 0.2 wave W0: spec
`mvp-0.1-baseline.9` (ADR 0008, POST-001), tested against server 0.3.0.

### Added

- `@openlfcp/client`, recovery after server data loss (ADR 0008,
  LFCP-WIRE-01 §41.1, §51.1, §68.1, §86, baseline.9):
  - **Both directions of anti-entropy.** On every `RESOURCE_OPENED`, on
    every `DATA_HAVE` or `CONTROL_HAVE` from the server and after
    `UNKNOWN_PREVIOUS`, the client uploads what the server lacks: the
    Control Records above the server's head (one `CONTROL_PUT` each, in
    order), then the accepted units its Have Vector lacks, ours and other
    actors' (relay), per actor in ascending sequence, never a unit held
    for its `previous`, quarantined, equivocating or still queued. A server
    that lacked something also gets the Key Packages we sent or received
    again, once per open. A refused batch is split; `ACTOR_EQUIVOCATION`
    for a relayed unit is expected and raises no alarm.
  - **`UNKNOWN_PREVIOUS`.** The outbound queue holds a refused unit (the
    new `NackOutcome` `"needs-offer"`, with the `previous` the server
    lacks) until the client has asked the server's Have Vector and offered
    what it lacks (`OutboundQueue.offered`); then it is sent again.
  - **Re-hosting.** `RESOURCE_NOT_HOSTED` for `RESOURCE_OPEN` from a route
    in the Resource's route set that hosted or opened it for this client
    before (a local mark) re-hosts it from the exact Genesis bytes, opens
    it again and offers it everything: the new `rehost` event, `outcome:
    "hosted"`. A refused re-host (`HOSTING_DENIED`, `QUOTA_EXCEEDED`,
    `RATE_LIMITED`, …) is `outcome: "refused"` with the code, and the
    Resource is refused (`resource-refused`, request `"rehost"`); it is
    not retried by itself. Otherwise `RESOURCE_NOT_HOSTED` stays terminal,
    as in 0.1.1.
- `@openlfcp/client` and `@openlfcp/storage`, POST-001 (SHARED-OBJECTS-PROFILE-01
  §14.1): a unit whose change another change's actor and sequence number
  already has is reported as the new `ApplyOutcome` `"profile-held"`
  (with `actor`, `seq`, `epoch` and `detail`) and stored with the new
  status `"profile-held"`. It stays LFCP-accepted: it is in the Have Vector
  and is relayed. After every rebuild that removes changes (an
  equivocation, a Key Epoch cutoff) it is retried, and a released unit is
  reported as `"applied"` in that event's `released`. A restart replays
  it. Profile handlers report held units in `ProfileBatchResult.held`,
  `ProfileApplyResult.held` and `ProfileExcludeResult.released`.
- `@openlfcp/wire`: the §62 code `UNKNOWN_PREVIOUS` (23), a server's
  refusal of a Data Unit whose `previous` it does not store (§51.1), and
  `haveDifference(local, remote)`, both directions of anti-entropy: what a
  replica requests and what it offers (§28, §68.1).
- `@openlfcp/client`: `acceptInvitation` can check the Resource's Data
  Profile before it claims (LFCP-02-086). The new option
  `dataProfiles` lists the profiles the caller can open. When the Genesis
  names another one, the join stops after the chain is fetched and the
  link's secret is checked, before the Key Package is fetched and before
  the `CAPABILITY_CLAIM`. It returns the new result
  `{ kind: "profile-unsupported", resourceId, code: "PROFILE_UNSUPPORTED",
  dataProfile }`, with the Resource's profile. Nothing is stored, and a
  one-time invitation stays unused for a client that implements the
  profile. Without the option nothing changes: any profile is claimed, as
  before.

### Changed

- `@openlfcp/client`, outbound queue (§51, §51.1): the units of one actor
  in a `DATA_PUT` go oldest first, since a server checks each unit's
  `previous` in message order. A unit refused with `UNKNOWN_PREVIOUS`
  whose `previous` is our own unit still queued waits for that unit's ACK,
  and that unit, lost on the way, is sent again at once. The request
  timeout now doubles per unanswered send in a row, no longer per attempt:
  answered refusals never lengthen it.
- `@openlfcp/client`, behaviour (LFCP-WIRE-01 §86, baseline.9): a Key
  Package the client opened is now stored (`keyPackages`), like the ones it
  sends, for as long as it keeps the Resource.
- `@openlfcp/shared-objects`, behaviour (POST-001, SHARED-OBJECTS-PROFILE-01
  §14.1): a change whose actor and sequence number another change of the
  document already has is now **held**, not refused with
  `ACTOR_EQUIVOCATION`. `SharedObjectsDataProfile` keeps it out of the
  document, reports it in `applyBatch().held` (and `apply().held`, with the
  reason), and retries it after every `exclude`: `exclude().released`
  lists the held units that merged. `heldUnits()` lists the held ones.
- The SDK implements spec `mvp-0.1-baseline.9` (SPEC-PATCH-09, ADR 0008
  and POST-001); the conformance runner checks its new vectors
  `have_difference` and `data_put_previous` (the server's `previous` rule,
  run as a second implementation).
- `@openlfcp/client`, types: `AcceptedInvitation` has the new variant
  `"profile-unsupported"`. It is returned only when `dataProfiles` is
  given, but a `switch` over `kind` that checks exhaustiveness needs a
  case for it.

## 0.1.1 — 2026-10-07

### Added

- `@openlfcp/client`: a refused Resource is a terminal, typed sync state
  (POST-017, sdk-ts cae7434). Before, a Resource the server refused stayed
  CLOSED but wanted, and a client waiting for it to be in sync hung until
  its own timeout. Now the refusing NACK is classified.
  - **Terminal.** A NACK of `RESOURCE_OPEN`, or of a Resource's reads
    (`CONTROL_GET`, `KEY_PACKAGE_GET`, `DATA_GET`, `DATA_HAVE`,
    `SNAPSHOT_GET`), whose code is in the new `TERMINAL_RESOURCE_CODES`:
    `RESOURCE_NOT_HOSTED`, `RESOURCE_NOT_FOUND`, `RESOURCE_TOMBSTONED`,
    `AUTHORIZATION_FAILED`, `PROTOCOL_UNSUPPORTED`, `MALFORMED_MESSAGE` and
    `PROFILE_UNSUPPORTED` (WIRE-01 §41, §62, §84).
    - The Resource is CLOSED, and `RESOURCE_CLOSE` is sent if it was
      subscribed.
    - `SyncClient.resourceRefusal(R)` returns a `ResourceRefusal`: the §62
      code, the server's diagnostic, the server URL and the refused request.
    - One `resource-refused` event is emitted.
    - The Resource is not opened again, not even after a reconnect, until
      `open()` is called for it.
  - **Transient.** Any other code on the open or a sync round
    (`RATE_LIMITED`, `INTERNAL_ERROR`, `QUOTA_EXCEEDED`, unknown codes) is
    retried on the same connection after the `ReconnectPolicy` delay for
    that Resource; the attempt count resets when the Resource is LIVE.
  - `KEY_PACKAGE_GET` keeps `KEY_BLOCKED`, and `SNAPSHOT_GET` keeps
    replaying the units. A refused `DATA_HAVE` is sent again by
    anti-entropy.
  - The `error` event is still emitted for every refusal.

### Changed

- `@openlfcp/client`, behaviour:
  - A Resource refused with a terminal code is no longer opened again
    after a reconnect. To ask again, call `open()`.
  - A transiently refused open is retried without waiting for a
    reconnect.
- `SyncEvent` has a new member, `resource-refused`. A `switch` over
  `SyncEvent.type` that checks exhaustiveness at compile time needs a case
  for it.

### Fixed

- The package READMEs install from `latest` instead of `next` (sdk-ts
  ce1c88e).

Live tests now run against the reference server 0.2.0 (`server.lock`
d6cd820).

## 0.1.0 — 2026-10-06

The OpenLFCP MVP 0.1 release of the eight packages, on the npm dist-tag
`latest` (sdk-ts 4e1b02f, tag `v0.1.0`). See the
[MVP 0.1 release notes](https://github.com/openlfcp/.github/blob/main/docs/release/mvp-0.1-release-notes.md).
