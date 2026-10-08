# Changelog

All eight `@openlfcp/*` packages are released together, at one version.
Until 1.0, a minor version may change APIs; a patch version does not
remove or rename any.

## Unreleased

### Added

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
