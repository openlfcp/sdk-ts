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
- `SectionReplica` in `@openlfcp/shared-objects/sections` (LFCP-02-012),
  Working Draft: the section writer. `commit(intents)` validates a batch as
  a whole and writes it as one change of the section actor:
  `section.create`, `section.set_title`, `section.mark_ready`,
  `task.create_in_section`, `paragraph.create`, `item.create`, `raw.create`
  (node, placement, children entry and `placement` register atomically,
  the caller's IDs, inserted after a visible sibling), and the Shared
  Objects Task intents on section Tasks. A refused batch writes nothing and
  throws `SectionIntentError` with a typed `code` and the intent's index.
  Authoring SS01 with the corpus identities reaches its reference state.
- `node.move` and `node.set_list_style` on `SectionReplica` (LFCP-02-013):
  a move writes a fresh immutable placement into the destination list
  after the visible predecessor and points the node's register at it; the
  node, its Task and its subtree keep their identity, and the old slot
  stays as an anchor. A move under itself or a descendant, or after itself,
  is refused. SS09 (repeated moves) and SS02 (concurrent inserts, merged)
  reach their reference states.
- `tree()` on `SectionReplica` and `SectionDocument`, and `deriveTree`
  (LFCP-02-014): the effective tree of a section and its structural facts
  (`PLACEMENT_CONFLICT` with its candidate placements, `PARENT_CYCLE`,
  `BLOCKED_PARENT`, `LIFECYCLE_CONFLICT`), hidden nodes and the
  classification, computed iteratively; every case of the corpus matches.
  `node.resolve_placement` and `structure.resolve` write explicit
  resolutions (SS15 and SS26 reach their reference states); `node.move` on
  a conflicted node is refused with `NODE_IN_CONFLICT`, and an intent
  naming no node with `UNKNOWN_NODE`.
- `node.delete` and `node.restore` on `SectionReplica` (LFCP-02-015): a
  Task node's lifecycle is its Task's, another node's its own; each is a
  fresh causal write, also for a value already visible, and descendants are
  never rewritten. `tree()` hides a deleted node and its subtree and
  reports `retainedConcurrentEdits` (EDIT_UNDER_DELETED_ANCESTOR) from the
  change history. SS07, SS08, SS24, SS25 and SS27, written through these
  intents, reach their reference states.
- `text.edit`, `paragraph.split`, `item.split` and `node.join` on
  `SectionReplica` (LFCP-02-016): edits of a node's existing Text in
  Unicode scalar positions against a base `modelRevision`, rebased onto the
  current Text through Automerge cursors (`STALE_BASE` when a deleted range
  changed); a split keeps the prefix in the node and gives the suffix to a
  new node right after it; a join appends the second node's text and
  deletes it with its Text history kept. SS06, SS14, SS16, SS17, SS40 and
  SS47 to SS51, written through these intents, reach their reference states.
- `receiveChanges` on `SectionReplica` (LFCP-02-017): received changes go
  through the inherited admission (framing, §11.1 expansion, the signer's
  actor, the sequence check, held changes of a taken actor sequence) and
  the section rules A1–A5 and §12.1 of SHARED-SECTIONS-PROFILE-01 §14.1,
  decided from each change's operations against its causal history, before
  the engine applies any; a refused change is never merged and the changes
  after it wait. Every case of the corpus, the injected negatives included,
  is admitted, refused or held as it expects. `SectionAdmissionError`
  carries the §14.1 diagnostic.
- Access recovery after a server restore (LFCP-02-106) in `SyncClient`:
  when RESOURCE_OPEN is refused with AUTHORIZATION_FAILED and the
  client's validated chain grants it `data/read`, it re-supplies the
  Control Records the server lacks with CONTROL_PUT, from the head the
  server reports, and opens again once; a revoked member sends nothing,
  and transient refusals are retried at most three times. New event
  `access-recovery` (`started`, `recovered`, `ended` with a reason).
- `SectionReplica.task(id)`: the Task of a section's task node with its
  conflict metadata, in the form of `SharedObjectsReplica.task(id)`
  (`TaskView`: status, problems, the provisional Task, every scalar
  register's concurrent values, tags and assignees), so a renderer of SOP
  Tasks works on section Tasks unchanged. Both replicas share one
  implementation.
- `SyncClient.canWrite(resource)` (SDK-SECTIONS-INTEGRATION-01 §6):
  `{ allowed, reason, controlHead, verifiedAt }` from the validated Control
  state only: `data/write` and the current epoch's DEK allow writing;
  otherwise `read-only`, `revoked`, `not-member`, `key-unavailable`, or
  `unknown` without a validated chain. `SyncClient.commit` refuses a batch
  while writing is not allowed with `NotWritableError` (`NOT_WRITABLE`,
  §3.6) and writes nothing; it threw `LfcpError` (`UNSUPPORTED_VALUE`)
  for a missing chain or DEK before.
- Batch status and the status stream (LFCP-02-026,
  SDK-SECTIONS-INTEGRATION-01 §4–§5) in `SyncClient`. A committed batch
  is `pending` until every unit is accepted: an ACK that answers our
  DATA_PUT, says durable, comes from a server whose READY promised
  durability 2 or more, and is on the Resource's route set. The
  acceptance is stored with the receipt in the ACK's dequeue transaction,
  so it survives a restart. Otherwise a batch is `evidence-unavailable`,
  `rejected` after a terminal NACK (with its code and units), or `saved`
  when it has no units. Units of a batch the server lost are reported as
  `reoffered` with the first signal (`unknown-previous`, `have-gap` or
  `rehost`): the batch is pending again until a new ACK. Received units
  are reported as `held`, `waiting` or `refused`, with the section state
  (`ready`, `importing`) and write access. Events come as `status` sync
  events, with a revision per Resource that grows by one per event;
  `statusSnapshot(resource)` gives the complete state at a revision. Also
  new: `batchStatus`, `batchStatuses`, `receiptsOf`,
  `SectionReplica.sectionState()`, and an optional `section()` on
  `CommitBinding`. `releaseReceipt` also forgets the batch's status.
  `OutboundQueue.onAck` takes an optional `also` that adds writes to the
  dequeue's transaction.
- `TypingCoalescer` (LFCP-02-025): one Data Unit per typing burst instead
  of one per key, in front of `SyncClient.commit`. A pass that only edits
  Text waits; the next pass on the same base replaces it (it contains its
  edits). A pass is committed when it holds another intent, leaves the
  paragraph, reaches 256 characters, after an idle pause of 1.5 s
  (`tick(now)`), or on `flush()`. A waiting pass has no receipt and is not
  durable: the adapter's source still holds it.
- `SyncClient.accessState(resource)` (LFCP-02-027): write access with its
  evidence. It includes `controlSeq` against the highest `serverControlSeq`
  a server reported in this session, with `current` false while the
  validated chain is behind. It also gives the effective `abilities` and
  the active grant `paths` that confer them. Apart from access, it lists
  the `invitations` we issued, our Control Records not committed yet
  (`pendingControl`) and an unsettled invitation claim (`pendingClaim`).
  The status stream's `access` event and `statusSnapshot().access` carry
  it, and an access event follows a server head that leaves the chain
  behind. A grant whose parent was revoked now counts as revoked.
- Section Snapshots (LFCP-02-028): `SharedSectionsDataProfile`
  `snapshotCodec()`, `snapshotState()`, `loadSnapshot(save)` and
  `snapshotBinding()` for `SyncClient`. A received Snapshot is loaded
  through the section admission, change by change, on an empty replica
  (`SectionReplica.mergeSave`). A Snapshot holding a change admission
  refuses is rejected with that diagnostic, and nothing changes. The
  replica's own changes, including local work the Snapshot lacks, are
  kept on top, and the §9 sequence carries over.
- A `catch-up` fact in the status stream and `statusSnapshot().catchUp`
  (LFCP-02-028). It is `receiving` while Control, keys and units are
  fetched, and `current-at-checkpoint` only once the Resource is live,
  with `checkedAt`. It stays so offline, as of that check. It is
  `unknown` while a Control conflict or a missing key blocks the catch-up.
- `SyncClient.commit` refuses a batch with `section.create`
  (`CommitRefusedError`, `SECTION_EXISTS`) when units of the Resource are
  stored, or when this client is not the Resource's owner and the
  Resource was not live in this session. An incomplete load never becomes
  a new, empty section (SHARED-SECTIONS-PROFILE-01 §13). The owner still
  creates its new Resource's section offline.
- `@openlfcp/storage-idb` opens its database at version 2 (`IDB_VERSION`,
  LFCP-02-029). A 0.1.x database (version 1) is kept as it is, with no
  store changed. A 0.1.x client then refuses the database (VersionError)
  instead of reading sealed checkpoints (LFCP-02-098) as plaintext.
  Downgrading is supported only to a client that knows version 2. A
  database of a newer client is refused with `UNSUPPORTED_VALUE` and left
  untouched.
- `conformance/upgrade/` (LFCP-02-029): storage written by the 0.1.3 SDK
  (SQLite with file secrets, and IndexedDB) opened by this one. The three
  queued edits, their exact bytes, the actor sequence, the key reference
  and the model are kept, sealed at rest or not, and the next edit
  continues the sequence. A section Resource is added beside it with its
  own profile and actor. A 0.1.x client then refuses the store. README
  "Local storage upgrades" gives the version matrix.
- `SyncClient`'s `snapshotPolicy` now counts the units this client commits
  through `commit`, not only the units it receives. A section's only
  writer reaches its threshold and publishes Snapshots.
- A key store that cannot be read is `key-unavailable` in `canWrite`,
  `accessState` and `commit` (`NotWritableError`), instead of an error
  from the DEK lookup (LFCP-02-030). Nothing is written, and no key or
  reference is removed.
- `SyncClient.revokeAccess(resource, subject, { rotate? })` (LFCP-02-060)
  removes a member's access:
  - Every active grant naming the member that this client may revoke is
    revoked (LFCP-WIRE-01 §17.3), which deactivates the grants delegated
    from it.
  - When the member has no read access left, the Data Epoch is rotated
    with a fresh DEK (§19, member revoked). The DEK goes in Key Packages to
    every other remaining reader.
  - Everything is built on the validated head and written in one
    transaction, the DEK first.
  - It returns the revoked and deactivated grants, the record IDs, the new
    epoch, the recipients, and the `remainingPaths` this revoker may not
    revoke.
  - It is refused, with nothing queued, when the Resource is not live
    (`offline`), the chain is behind the server (`stale`), Control Records
    of this client are pending (`control-pending`), and for
    `would-remove-owner`, `not-member` and `not-authorized`.
  - `planRevocation` is the pure planner, and `controlRecordWrites` and
    `keyPackageWrites` queue in a caller's transaction.
- A refusal of the Resource is reported in the status stream
  (LFCP-02-115):
  - When the server refuses this client the Resource
    (`AUTHORIZATION_FAILED` on `RESOURCE_OPEN`) and access recovery does
    not help, `accessState`, `canWrite` and `commit` report `allowed: false`
    with the reason `server-refused`, `current: false`, and
    `serverRefusal: { code, recovery }`, where `recovery` is how the access
    recovery ended.
  - It is never reported as "revoked": the server does not say why.
  - Unaccepted batches are `blocked`, with the work kept; catch-up is
    `unknown`.
  - Events report each change, and `open()` again clears the refusal.

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
