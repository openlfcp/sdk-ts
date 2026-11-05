# Changelog

All eight `@openlfcp/*` packages are released together, at one version.
Until 1.0, a minor version may change APIs; a patch version does not
remove or rename any.

## 0.3.1 — unreleased

A patch of 0.3.0: one fix and one additive API, both found by the plugin's
end-to-end device scenarios (LFCP-04-414, decision I17). Dated when tagged.

### Fixed

- The final frontier of a key rotation (`rotateAfter`, `verifiedFrontier`)
  counted units that no recipient can merge: they were checked for
  signature, authorization and the actor chain, but not for decryption or
  the Data Profile. A unit that fails AEAD (for example junk signed with an
  actor's key and accepted by the server) became the actor's latest unit,
  and the honest units after it fell beyond the cutoff and were quarantined
  (`STALE_DATA_EPOCH`) after a device removal. A unit now counts only when
  it decrypts under its epoch's DEK and, when the application passes its
  codec in the new `FlowOptions.dataProfiles`, the Data Profile accepts it
  (LFCP-WIRE-01 §26.3 rules 6 and 7, §19; IDENTITY-PROFILE-01 §8.3); units
  this installation recorded as refused stay out. `verifiedFrontier` takes
  this as an optional fourth argument (`FrontierData`); without it the 0.3.0
  checks apply.

### Added

- `addToRoster`: adds a Resource to the roster of the Identity Resource as a
  journaled operation, so a Resource created or joined after `I` was filled
  (for example a section created after pairing) reaches the human's other
  devices (IDENTITY-PROFILE-01 §2.1, §6). Idempotent (`present` when the
  roster already lists it), written again after a stale refusal,
  `document-incomplete` and resumable after another refusal, `needs-writer`
  on a device that cannot write `I`. `writeRosterEntry` is the durable phase
  `acceptInvitationAsDevice` and `createResourceAsDevice` share.

## 0.3.0 — unreleased

The first release of the 0.3 line, published under the npm dist-tag `latest`:
MVP 0.4, multi-device identity (one person, several devices). It adds APIs and
changes some results of the identity flows; read the notes below before
upgrading from 0.2.2. Dated when tagged.

### Conformance, differential and headless pairing (LFCP-04-412)

Multi-device identity, T4 (LFCP-04-412): conformance on all three identity
corpora, a differential run against sdk-rs, live identity flows against the
reference server, and headless pairing.

- Conformance runs every case of the three identity corpora as a suite:
  all 387 of LFCP-IDENTITY-TEST-VECTORS-01 (before: the 196 Control Records,
  with four post-state fields), with the whole post-state of W §79 the
  corpus lists, certificate chains, Data Units with their plaintext, Key
  Packages and the Key Package matrix, Snapshots, session reads and uploads
  (W §41) and the rotator test; the 191 of IDENTITY-PROFILE-TEST-VECTORS-01;
  and the 22 fixtures of IDENTITY-FLOW-FIXTURES-01 step by step. A step
  is not applicable by the text (another client generation, the server's
  duty) is reported as such, and one that applies but that the harness cannot
  drive on a fixture's bytes (a journal, a UI decision, a network) as not
  verified, each with its reason: runner parts of their own, in the summary
  (a case with not-verified parts is "incomplete"), never a pass and never a
  todo.
- With `LFCP_IDENTITY_REPORT_DIR` set, each identity suite exports what
  sdk-ts decided for every case in the `lfcp-identity-outcomes/1` format
  sdk-rs exports too. `scripts/identity-differential.mjs` compares the two
  exports case by case and step by step: required fields on both sides,
  state tables by membership, a field only one side reports only when
  `conformance/identity/differential-schema.json` documents it. Every
  divergence must be explained, with the side the text supports, in
  `conformance/identity/differential-known.json`. Against sdk-rs `750ac8f`:
  one, F13 step 1 (sdk-rs reports a certificate signed before phase 1;
  sdk-ts is right by §5.3 step 5).
- The live identity tests are skipped, with the reason, without a server
  (and fail with `LFCP_REQUIRE_LIVE=1`), never reported passed.
- `server.lock` pins the reference server at `c12c3dd` (identity-01 at
  `mvp-0.4-baseline.2`, hosting by the Genesis owner, the Control read of a
  revoked reader). `rust-server-identity.test.ts` runs pairing, approval,
  the same-root Key Package, revocation with rotation and the cascade, and a
  revoked device's Control read and proof against it over a real WebSocket.
  `LFCP_SERVER_BIN` runs the live tests on a prebuilt server binary.
- `@openlfcp/storage-node`: `lfcp-node pair`, the headless pairing of a
  service device (IDENTITY-PROFILE-01 §5.3, decision I6): the sections by
  roster name, the fingerprint printed, the result from the chain, resumable.
  The package now depends on `@openlfcp/client`, `wire`, `crypto` and
  `shared-objects`, and is published after `client`.
- `@openlfcp/client`: `requestPairing` takes `sections`, roster names
  resolved after the link is verified (`unknown-sections` when one matches
  no entry or several, nothing written); `completePairing`'s candidates carry
  their roster `name`.


Multi-device identity, wire codecs (LFCP-04-405, against openlfcp/spec PR 2,
LFCP-WIRE-01 §7.2, §7.3, §14, §15, §17.4, §17.5, §23.3, §62). The spec pin
is `mvp-0.4-baseline.2` (LFCP-04-409b, below).

### Spec pin: `mvp-0.4-baseline.2`

- `spec.lock` pins `mvp-0.4-baseline.2` (`2af5d97`), moving from
  `mvp-0.2-baseline.12` with the changes of `mvp-0.4-baseline.1` and
  `mvp-0.4-baseline.2` (`migrations/mvp-0.4-baseline.*/value-changes.json`).
  The identity corpora are read from the pinned tag like every other suite:
  `conformance/identity/spec3.mjs` and its pin on spec PR 3 (`ff81262`) are
  gone.
- Conformance runs IDENTITY-PROFILE-TEST-VECTORS-01 as a suite (all 191
  cases: framing, admission AI0 to AI5 with the writer class taken at the
  unit's `control_ref`, per-entry validation, the replica scenarios, pairing
  links, fingerprints, the approval digest, rootOf tables), every Control
  Record case of LFCP-IDENTITY-TEST-VECTORS-01 with its verdict, wire code
  and post-state (owner, sequence, epoch, rootOf table), and
  `READY_identity_01` byte for byte. The CDDL fixture run decodes the
  `invalid-device-*` fixtures. `unknown_core_type_C1` uses type 31 and is
  `INVALID_CONTROL_CHAIN` again: the runner's superseding entry for type 9
  is removed.
- `@openlfcp/shared-objects/identity`: admission rule AI5
  (IDENTITY-PROFILE-01 §3, decision I8). A change that creates, writes or
  deletes `devices[k].missing_keys`, or anything inside it, is
  `UNAUTHORIZED_WRITER` unless it is signed by the Principal `k` names (the
  root for its own entry); deleting or replacing the entry itself is not
  such a write. Entry maps are those created in the causal history, values
  the engine does not select and maps since replaced or deleted included.
  Concurrent writes are each decided by themselves: the device's is
  admitted, the other refused with its dependants.
- `@openlfcp/shared-objects/identity`: AI2 is decided on the objects a write
  names as its predecessors, not on the values visible at its dependencies.
  A scalar whose operation replaces no object is admitted even beside a list
  in the same field (§4 then judges the field), and a scalar over a map held
  in an entry field is `CONTAINER_REPLACED`, as over a list. AI2 has two
  levels only, an entry map and a list or map in one of its fields: a scalar
  over a deeper list (`devices[k].missing_keys[X]`, an unknown field's
  value) or over a list standing in place of an entry map is admitted and
  left to §4, where it was `CONTAINER_REPLACED` (review of sdk-ts#16).
- `@openlfcp/wire`: the new epoch number of a `KEY_EPOCH` is checked in chain
  placement (LFCP-WIRE-01 §19, §62 class 2, decision I9), before
  dependencies, signatures and authority: a wrong number is
  `INVALID_CONTROL_CHAIN` even when the signature does not verify
  (`INVALID_SIGNATURE` before) or the issuer is unknown
  (`MISSING_DEPENDENCY` before).
- `@openlfcp/client`: `revokeDevice` sets a revoked device's `revoked`
  display flag without rewriting the device's `missing_keys` hint. It used
  to copy the whole entry, so the write was refused for any device with a
  hint, and the refusal, display data only, was dropped silently.
- A rejected pairing link (IDENTITY-PROFILE-01 §5.2) stays a client-local
  outcome with no wire code: `requestPairing` reports `invalid-link` or
  `not-a-session` and sends nothing more as the pairing device. The corpora
  name it `PAIRING_LINK_REJECTED`; the SDK's parsers throw the client-local
  `INVALID_INVITATION`.

### Identity document writes: no silent success (LFCP-04-410c)

A unit of the Identity Resource's document that the coordinator refuses
is no longer dropped while the flow answers success (review of sdk-ts#16,
P2). Each flow rebuilds a unit refused as `STALE_DATA_EPOCH` on the
current state (W §19.1), reports any other refusal and keeps its operation
open, and a resumed operation writes the unit again (`runUnitPhase`
`rebuildRefused`; reconciliation has no resume, see below). The Control
Records already committed stand. When the state a unit is built on
already holds its effect, written by another writer since the flow's
first read, nothing is sent and the phase is `complete` (a `build` that
returns null).

- `approvePairing` / `resumeApproval`: `document-incomplete` (with the
  device, chain, registrations, rotation and the code) when the device
  entry and the request removal of §5.3 step 6 are refused; the operation
  stays open.
- `cancelPairing` with `reject`: `document-incomplete` when the request
  deletion is refused; `J` is cancelled, the session stays open, and the
  same call writes the deletion again.
- `reconcileDevices`: a `document` result (`DocumentWrite`: `none`,
  `committed-own`, `complete`, `refused`) for the entries of §7.1 step 4,
  built on the current state of `I`. `complete`: another manager wrote the
  missing entries meanwhile, and the operation is done. A refusal leaves the
  operation open. There is no resume: a later `reconcileDevices` is a new
  operation that proposes the entries still missing then; it does not close
  the open one.
- `revokeDevice`: a `document` result for the `revoked` flag of §8.2:
  `none` when the device has no entry (also when another writer deleted it
  meanwhile), `complete` when another writer set the flag, and `refused` or
  `unreachable`, which leave the operation open; `revokeDevice` with that
  `operation` writes the flag again. The display write no longer drops
  every error: only `IdentityUnavailable` is caught, and the revocation
  goes on to the roster; any other error is thrown.
- `loadIdentityDocument`: `unapplied` names the units the wire accepted
  whose change the document did not take (refused or held).

### Added

- `@openlfcp/wire`: Device Certificates and certificate chains
  (`parseDeviceCertificate`, `signDeviceCertificate`,
  `certificateChainFromCbor`, `certificateChain`), the payload digest, the
  kind, mask and scope rules, `verifyChain` in the class order of §62 with
  read-only `ChainStateChecks`, and `preflightIssuance` for a leaf that is
  not signed yet.
- `@openlfcp/wire`: the `DEVICE_GRANT` (9) and `DEVICE_REVOKE` (10) records,
  Genesis field 5 and transfer commit field 2 are verified and applied
  (LFCP-WIRE-01 §17.4, §17.5, §15, §23.3): `ControlState` carries `roles`,
  `devices` and `revoked` (§79) and grants carry `issuerRoot`. Device
  activity with the revocation cascade and root standing, `actsFor`,
  `rootOf`, `ownerAction`, `sameRoot`, two-phase pairing approval and role
  exclusivity follow §80.1. `hasAbility` is `holds` (§80.1), so Data Units,
  Snapshots and Key Packages are judged with devices too; a chain without
  device records gives the same answers as before.
- `@openlfcp/wire`: pairing links (`lfcp://pair/…`, `parsePairingUri`,
  `assemblePairingUri`, `pairingDeviceSigner`) and `deviceFingerprint`
  (IDENTITY-PROFILE-01 §5.2).
- `@openlfcp/wire`: `exposedReaders` / `isExposingRevocation` (W §17.5
  Exposure) and `revokedReaderPrefix` (W §41 control read for a revoked
  reader); `authorizeDeviceGrant` and `authorizeDeviceRevoke` are exported.
- `@openlfcp/client`: the identity flows of IDENTITY-PROFILE-01 (LFCP-04-410,
  checked against IDENTITY-FLOW-FIXTURES-01 of `mvp-0.4-baseline.2`):
  the durable operation journal, the §9.2 phase classifier and the package
  ledger (§9); `createIdentityResource` (§5.1); pairing on the managing side
  (`createPairingSession`, `pairingRequests`, `approvePairing`,
  `cancelPairing`, resumable) and on the new side (`requestPairing`,
  `completePairing` with the §6 statuses); `registerDevice`,
  `reconcileDevices` (§7.1), `previewRevocation` and `revokeDevice` with the
  rotator test, the verified frontier and the rotation policy by exposure
  (§8); `acceptInvitationAsDevice` and `createResourceAsDevice` (§7.2, §7.3);
  `revocationStatus` (§8.6). The flows talk to coordinators through an
  `IdentityNetwork` port (`connectionNetwork()` over `LfcpConnection`) and to
  the Identity Resource's document through an `IdentityDocumentPort` backed
  by `@openlfcp/shared-objects`' `IdentityReplica`.
- `@openlfcp/shared-objects`: `IdentityReplica.write` takes several intents
  for one change; `IdentityReplica.origins` names the admitted changes that
  wrote an entry, with their signers (the provenance a pairing approval
  checks and journals).
- `@openlfcp/client`: a durable write barrier per Resource
  (`writeBarrier`, `setWriteBarrier`): `revocationStatus` sets it on a
  refused read or a proven revocation (IDENTITY-PROFILE-01 §8.6), and
  `createQueuedDataUnit`, `commitOperation` and the identity flows refuse
  to write behind it.

### Changed
- `planRevocation` (and `SyncClient.revokeAccess`) seal the new DEK to every
  Principal holding `data/read` at the new head, and a revoker that is not
  the rotator of IDENTITY-PROFILE-01 §8.1 revokes without a Key Epoch and
  reports `awaitingRotation` instead of refusing.

- A record of type 9 is no longer an unknown core type: a type-9 record
  whose body is not a `device-grant-body` is `MALFORMED_MESSAGE`, not
  `INVALID_CONTROL_CHAIN` (baseline.12's `unknown_core_type_C1`, which
  `mvp-0.4-baseline.1` moves to type 31).
- Structure before placement (§62): a transfer commit's offer and accept
  are parsed with the commit, so a malformed one is `MALFORMED_MESSAGE`
  even when the commit is misplaced or its issuer unknown; a misplaced
  Genesis with a malformed body is `MALFORMED_MESSAGE`, not
  `INVALID_CONTROL_CHAIN`. A writer refuses a commit whose offer or accept
  is not a transfer object.
- A transfer offer's signer is never a dependency (§23.3, §62 class 4,
  spec PR 2 `e7fc88c`): the offer is verified under its kid only when that
  kid is the owner or a device bound to the owner; any other offer, known
  or not, valid or not, is `AUTHORIZATION_FAILED` (was `INVALID_SIGNATURE`
  for a known outsider, `MISSING_DEPENDENCY` for an unknown one). A bad
  owner, owner-device or accept signature stays `INVALID_SIGNATURE`.
- `canDistributeKey` also accepts a sender of the recipient's root
  (`sameRoot`, §25.2).
- Device records follow spec PR 2 `7d75f7d`/`bc03b0f`: a device submits
  only its own first registration (§17.4 rule 6); a `DEVICE_GRANT` may not
  bring a root above 32 live bound devices nor be the ninth for one root
  and leaf (§17.4 rule 8); a root may revoke at most 64 unbound Principals
  (§17.5 rule 5). `ControlState` carries the counters (`liveBound`,
  `preemptive`, `preemptiveRoots`, `DeviceBinding.grantsAccepted`).
- The issuer of a `DEVICE_GRANT` or `DEVICE_REVOKE` is never taken from
  `resolvePrincipal`; a record's kid must be its issuer, and with commit
  field 2 the issuer must be the leaf (`INVALID_SIGNATURE` under any
  policy).
- `ControlState` maps (`principals`, `roles`, `devices`, `revoked`,
  `grants`) are persistent (`PersistentMap`): the states `stateAt` keeps
  share their entries: a persistent AVL tree over the full key, so no
  choice of keys makes an update copy more than one path. They are
  `ReadonlyMap`s as before; they iterate in key order, not insertion.
- The certificate scan also checks the COSE envelope, the descriptor's
  fixed fields and a Genesis with a null prev before any decoding.

## 0.2.2 — 2026-10-16

A patch of the 0.2 line, published under the npm dist-tag `latest`: it is 0.2.1
plus the fixes below and one additive method, `onListenerError`; nothing is
removed or renamed. Dated when tagged.

### Fixed

- `createInvitation` is atomic (LFCP-03-044). It used to queue the
  invitation grant and its Key Package in two commits and build the link
  after both, so a failing second commit left the grant queued without its
  package, and endpoints the link cannot carry were refused only after both
  were queued. The link is now built and checked first, and the grant and
  the Key Package are stored in one commit, the grant first: a commit that
  throws or is refused queues neither, and the call can simply be repeated.
- A `SharedSectionsDataProfile` nodes-changed listener that throws no longer
  interrupts the operation that changed the model (LFCP-03-044). A remote
  merge, a recorded local batch, an exclusion, a reset or a loaded Snapshot
  used to throw although its change was already applied, and the listeners
  after the throwing one missed the event. Every listener now gets the
  event, the operation completes, and the error goes to the new
  `onListenerError` handler (or, without one, to the runtime's
  `reportError` where it has one); a handler that throws is not reported
  again. An engine trap in a listener is still thrown on, once every
  listener has had the event.
- The same for a `SharedObjectsDataProfile` object-changed listener
  (LFCP-03-044): a merge, an exclusion, a reset or a loaded Snapshot no
  longer throws after the replica changed, every listener gets every
  change, and the error goes to `onListenerError` (or `reportError`), with
  the same engine-trap rule.
- For both profiles: without an `onListenerError` handler, a listener's
  error goes to the runtime's `reportError` where there is one (a browser,
  Electron), and is dropped otherwise. Node has no `reportError`: register
  `onListenerError` there to see these errors.

### Added

- `onListenerError(handler)` on `SharedSectionsDataProfile` (failure type
  `SectionsListenerFailure`, `@openlfcp/shared-objects/sections`) and on
  `SharedObjectsDataProfile` (`SharedObjectsListenerFailure`,
  `@openlfcp/shared-objects`): where a throwing change listener's error is
  reported. Additive; nothing else in the API changes.

## 0.2.1 — 2026-10-15

A patch of the 0.2 line, published under the npm dist-tag `latest`: it is 0.2.0
plus the fixes below, with no API change. Dated when tagged.

### Fixed

- `SyncClient.commit` no longer reverts a batch it has stored (LFCP-03-034).
  It used to call `StagedOperation.revert()` when a step after the durable
  store threw: the send, when the connection dropped while the outbound
  queue was read (`ConnectionNotReady`), or a listener of the batch's status
  event or of the profile's `committed()`. The stored units still went out,
  so collaborators got the change while this device's model lost it, and
  the revert rewound the section replica's own change sequence, so a later
  local change could reuse the lost change's sequence and collaborators
  could not apply it. Once stored,
  a batch now stands: a failed send leaves it queued for the next
  connection, any other failure after the store is reported as an `error`
  event (`INTERNAL`), and the commit returns its receipt. A failure before
  the store still reverts the staged batch.
- `publishSnapshot` and `revokeAccess` no longer fail after they queued
  their objects when a listener throws or the connection drops before the
  send; the Snapshot or the revocation stands and is sent later.
- A `SyncClient` listener that throws no longer interrupts the SDK's own
  work: an ACK still dequeues and records what it acknowledges, received
  units and a loaded Snapshot still finish their catch-up, and every other
  listener still gets the event. The failure is reported as an `error` event
  (`INTERNAL`, with the Resource when the event has one); a listener that
  throws on that report too is not reported again. An engine trap in a
  listener is thrown on, as in 0.2.0: reached from message handling it
  stops the session (`ENGINE_TRAP`); a call such as `commit`,
  `publishSnapshot` or `revokeAccess` rejects with it, without stopping
  the session.

## 0.2.0 — 2026-10-14

The 0.2 line is final: published under the npm dist-tag `latest`, which
moves from 0.1.5 (0.1.4 and 0.1.5 came from the 0.1 maintenance line;
0.1.5's D1 table guard is rule R10 here). It is the code of
`0.2.0-beta.10`, with no change but the version. The SDK is read at spec
`mvp-0.2-baseline.12` and tested against the reference server at
`138030a`. The beta sections below give each change in detail; this
section sums up what 0.2 adds to 0.1.x.

### Added

- Shared Sections (SHARED-SECTIONS-PROFILE-01, `@openlfcp/shared-objects/sections`):
  `SectionReplica`, the section writer and reader: sections with Tasks,
  paragraphs, list items and raw blocks; moves, deletion and restore; Text
  edits, splits and joins; the effective tree with its structural facts
  (placement conflicts, parent cycles, lifecycle conflicts, retained
  concurrent edits) and their explicit resolutions; section Snapshots; and
  `validateSection` and the schema checks against the whole corpus (SS01 to
  SS94) (beta.1 to beta.7).
- The Shared Objects admission as a module every profile shares
  (`@openlfcp/shared-objects/admission`), with the §11.4 reference rules R8 to
  R10 and the later byte, sequence and actor checks (beta.1, beta.2).
- The section-aware sync client: batch status and the status stream, commit
  receipts, write access with its reason (`canWrite`, `accessState`), the
  catch-up fact, the `TypingCoalescer`, access recovery after a server
  restore, `revokeAccess` with Data Epoch rotation, re-proposal of Control
  Records a moved head refused (`reproposeControlRecords`, the `repropose`
  event, `localControlChain`), and `deleteUnsentResource` (beta.1, beta.6,
  beta.7).

### Changed

- Concurrent equal values of a scalar register agree (§45; SS86): no
  conflict for two equal completions, restores, placements or titles
  (beta.7).
- After a member's first unit went stale, its next unit names no previous
  unit (LFCP-WIRE-01 §26.2); an explicit null previous is refused while an
  accepted own unit exists (beta.8).
- A send on a connection that closed meanwhile throws `ConnectionNotReady`
  instead of an `INTERNAL` error event (beta.7).

### Fixed

- A section's replica no longer keeps an old copy of the document per
  unchanged task: memory stays flat as the history grows
  (`SectionReplica.stage`, `apply`, `revert`) (beta.9).
- A confirmation that arrives after its request timed out is still matched
  to its request, so the batch is confirmed instead of staying
  "confirmation unavailable" (`OutboundQueue.onAck`) (beta.9).
- A section with deleted tasks stays fast as its history grows: retained
  concurrent edits are decided with vector clocks, the decoded history is
  reused from one revision to the next, and the tree and snapshot are
  derived once per revision's heads (`SectionReplica.snapshot`, `tree`);
  the results are as before (beta.10).

### Upgrading from 0.1.x

- `@openlfcp/storage-idb` opens its database at version 2: a 0.1.x database
  is kept as it is and opens; a 0.1.x client then refuses the upgraded
  database (VersionError). Going back is supported only to a client that
  knows version 2. README "Local storage upgrades" gives the matrix, and
  `conformance/upgrade/` covers 0.1.3 storage (beta.1).
- Until 1.0 a minor version may change APIs: the Shared Sections API is
  new in 0.2, and the Shared Objects API of 0.1.x is kept.

## 0.2.0-beta.10 — 2026-10-14

A fix release. The SDK is still read at spec `mvp-0.2-baseline.12` and tested
against the reference server at `138030a`; nothing else changes. Published
under the npm dist-tag `beta`, like the earlier 0.2 betas.

### Fixed

- A section with deleted tasks stays fast as its history grows. Deciding
  which edits were concurrent with a deletion compared every change with
  all its ancestors, on every read of the section's tree: after a few
  thousand changes, each read took a second or more. Concurrency is now
  decided with vector clocks, the decoded history is reused from one
  revision to the next, and the tree and snapshot are derived once per
  revision (`SectionReplica.snapshot`, `tree`). The results are as before.

## 0.2.0-beta.9 — 2026-10-14

A fix release. The SDK is still read at spec `mvp-0.2-baseline.12` and tested
against the reference server at `138030a`; nothing else changes. Published
under the npm dist-tag `beta`, like the earlier 0.2 betas.

### Fixed

- A section's replica no longer keeps an old copy of the document per
  unchanged task: memory stays flat as the history grows. Each commit made
  its change on a copy of the document and kept that copy, and every task
  unchanged since an earlier commit kept that commit's whole document alive:
  with 170 tasks and 2,000 changes, about 1.6 GB of WebAssembly memory. The
  replica now applies the change to its own document and frees the copies
  it makes (`SectionReplica.stage`, `apply`, `revert`); change bytes,
  refusals and rollback are as before.
- A confirmation that arrives after its request timed out (a long pause in
  the app, when the timeout check runs before the waiting answer) is still
  matched to its request, so the batch is confirmed, instead of staying
  "confirmation unavailable" for good. Such a late ACK removed the items
  but was taken as uncorrelated, so it was no acceptance evidence (§4.1),
  and nothing could confirm the batch afterwards. The outbound queue now
  remembers the most recent expired requests (`OutboundQueue.onAck`).

## 0.2.0-beta.8 — 2026-10-13

A fix release. The SDK is still read at spec `mvp-0.2-baseline.12` and tested
against the reference server at `138030a`; nothing else changes. Published
under the npm dist-tag `beta`, like the earlier 0.2 betas.

### Fixed

- After a member's first unit in a Resource went stale (for example, an access
  change made while the member was offline cut it off), the member could never
  write to that Resource again: its next unit was refused for naming no
  previous unit. The next unit is now sent with no previous unit, as
  LFCP-WIRE-01 §26.2 requires, and a peer that accepted nothing of that member
  links it.
- An explicit null previous unit is refused while the writer still holds an
  accepted unit of its own in the Resource, before a sequence number is used:
  a peer that accepted that unit would hold the new one for good (§26.2). The
  default, the latest accepted own unit, is unchanged.

## 0.2.0-beta.7 — 2026-10-13

The SDK is read at spec `mvp-0.2-baseline.12` and tested against the reference
server at `138030a`. Concurrent equal values of a scalar register now agree,
as baseline.12 makes normative. Published under the npm dist-tag `beta`, like
the earlier 0.2 betas.

### Changed

- Concurrent equal values of a scalar register agree (SHARED-OBJECTS-PROFILE-01
  §45; SHARED-SECTIONS-PROFILE-01 §2, §7). A field is conflicted only when its
  concurrent values differ, and its conflict set lists its distinct values.
  Equal means the same Automerge scalar type and the same value; a map, a list
  or Text equals no other value. Two peers that each complete a Task, or each
  restore it, now produce no conflict. In shared sections, equal lifecycle,
  placement and title assignments agree: equal placements are no
  `PLACEMENT_CONFLICT`, and two concurrent deletions are no scalar conflict
  (SS86).
- A send on a connection that closed while a handler worked is no longer an
  `error` event with code `INTERNAL`. The connection's closing starts the next
  round at the next READY. Such a send throws `ConnectionNotReady` (still an
  `LfcpError` `UNSUPPORTED_VALUE`), and a request is registered only once it is
  sent.

### Added

- `delete-resource` storage write and `deleteUnsentResource`: forget a Resource
  this client made and never sent, every row of it in one commit, then its Data
  Epoch keys. Refused with `RESOURCE_SENT` (nothing of the batch written) when
  an outbound item was attempted, an ACK recorded, or anything of another
  Principal stored. In the memory, SQLite and IndexedDB adapters, and in the
  shared storage contract.
- `resourceSent`, the rule the adapters share, and `ConnectionNotReady`.

### Conformance

- `spec.lock` pins `mvp-0.2-baseline.12` (`bf1c78c`), `server.lock` the server at
  `138030a`. The new vectors pass: S17 to S19, SS92 to SS94, the Automerge
  reference corpus and the changed SS86; the baseline.11 Wire negatives (Haves
  of `RESOURCE_OPEN` and `RESOURCE_OPENED`, the envelope before the type)
  already passed.

## 0.2.0-beta.6 — 2026-10-12

A control-plane fix (LFCP-02-A): Control Records a client authored while an
earlier one of its own was still unacknowledged no longer stall forever.
Published under the npm dist-tag `beta`, like the earlier 0.2 betas.

### Fixed

- `createInvitation` builds the grant on the client's LOCAL Control Head — the
  committed chain extended by its own still-queued records — not the committed
  head, so two invitations made back to back chain on each other (consecutive
  sequence numbers, a linear `previous`) instead of colliding on commit and
  each other's `CONTROL_HEAD_MISMATCH` (§47).
- A Control Record the coordinator refuses with `CONTROL_HEAD_MISMATCH` is now
  re-proposed on the current head: re-authored with the same intent (a grant
  keeps the same Invitation Principal and claim parameters), re-signed, and its
  dependent Key Packages re-sealed to the new head; a record no longer
  authorized or meaningful is dropped with a typed outcome (`repropose` event).
  Re-proposal is bounded and idempotent, and recovers records persisted as
  "repropose" by an earlier version at the next open. Without it, such a record
  — and the invitation Key Package and link that depend on it — waited forever.
- A copied invitation link keeps working after its grant is re-proposed:
  `acceptInvitation` resolves the grant by its subject (the Invitation
  Principal) when the link's record ID is no longer on the chain (§18.2).
- `revokeAccess` still refuses with `control-pending` while a Control Record is
  pending (a revocation rotates the Data Epoch, so it is serialized, not
  chained); with re-proposal in place the refusal is temporary and a retry
  succeeds.

### Added

- `reproposeControlRecords` and the `repropose` SyncEvent (re-proposal outcomes),
  and `localControlChain` (the committed chain extended by own pending records).

## 0.2.0-beta.5 — 2026-10-12

The SDK is read at spec `mvp-0.2-baseline.10`, which makes three
SHARED-SECTIONS-PROFILE-01 rules explicit (findings E1, E2 and F1) and adds
cases SS88 to SS91. The production SDK already met them, so no package behaviour
changes; the fixes those findings name are in the Rust SDK. Published under the
npm dist-tag `beta`, like the earlier 0.2 betas.

### Conformance

- Baseline.10 states that §14.1's sequence checks count every change of the
  document, so a change at a taken sequence number is held before a section rule
  would refuse it (finding E1); that A5 refuses a scalar written to a node's
  `text` whatever the node's kind, even when the merge shows a Text (finding E2);
  and that a refused chunk whose dependencies or actor do not read is named too
  (finding F1). The production engine already behaved this way; SS88 to SS91
  confirm it.
- The shared-sections conformance adapter now counts a change held at a taken
  sequence number (`ACTOR_EQUIVOCATION`, §14.1) among the held rather than the
  refused, and treats SS88's order-dependent refusal in reverse delivery as the
  reference verifier does, so every case passes in each delivery order.

## 0.2.0-beta.4 — 2026-10-11

The SDK is read at spec `mvp-0.2-baseline.9`, which refines how a Shared
Sections re-deletion clears a retained concurrent edit
(SHARED-SECTIONS-PROFILE-01 §9). Published under the npm dist-tag `beta`,
like the earlier 0.2 betas.

### Fixed

- A retained concurrent edit (`EDIT_UNDER_DELETED_ANCESTOR`, §9) is now
  compared only with the deletions the lifecycle register still holds. A later
  write to the same register — one that has the deletion in its dependencies —
  supersedes it, so deleting the node again clears the attention a concurrent
  edit or move raised. Two concurrent deletions supersede neither and both
  count, and the writes are read from each change's operations so a deletion
  merged after a concurrent one still counts. At baseline.9 SS83 to SS87 cover
  it: SS83 and SS85 clear the attention by deleting again, SS84 keeps an edit
  concurrent with the new deletion, and SS86 (surfaced) and SS87 (cleared) are
  the two-concurrent-deletions pair.

## 0.2.0-beta.3 — 2026-10-11

The SDK is read at spec `mvp-0.2-baseline.8`. It refines how a refused
Shared Sections change is named (SHARED-SECTIONS-PROFILE-01 §14.1) and surfaces
a move concurrent with a deletion that hides it (§9). Published under the npm
dist-tag `beta`, like the earlier 0.2 betas.

### Fixed

- A refused change is named by its hash (the SHA-256 of the chunk from its type
  byte on) only when its checksum matches (finding C1). The checksum is the
  first four bytes of that hash, so a wrong-checksum copy was named by its
  intact copy's hash; it is now left unnamed, and the intact copy is checked on
  its own. At baseline.7 SS45 loses its name and SS76 to SS78 cover the twin
  copies; SS78's intact copy signed by another Principal is refused with
  `CHANGE_ACTOR_MISMATCH`.
- A refused change whose inner header holds a length running past the chunk's
  end is now named too (finding C3): §14.1 names a type 1 chunk from its outer
  length and checksum without reading the header, and `refusedChangeHash` no
  longer bails on that malformed header. At baseline.8 SS79 covers it: such a
  change is refused with `INVALID_AUTOMERGE_BYTES` and named.
- A move of a node (a write to its `placement` register — `node.move` or
  `node.resolve_placement`, SHARED-SECTIONS-PROFILE-01 §8) concurrent with a
  deletion of the node or of an effective ancestor is now a retained concurrent
  edit (`EDIT_UNDER_DELETED_ANCESTOR`, §9), the same as a title or Text edit;
  a move causally after the deletion is not. At baseline.8 SS80 to SS82 cover it.

## 0.2.0-beta.2 — 2026-10-11

The SDK is read at spec `mvp-0.2-baseline.6`. This beta adds the last of the
differential-fuzzing convergence between the two reference SDKs and moves the
spec pin up to `mvp-0.2-baseline.6`. Published under the npm dist-tag `beta`,
like `0.2.0-beta.1`.

### Added

- The sequence admission refuses, before the engine, a later change whose
  Automerge extra bytes begin with an author — an unsigned LEB128 1, a length
  and that many bytes — when its sequence number is not 1, with
  `INVALID_AUTOMERGE_BYTES` (SHARED-OBJECTS-PROFILE-01 §14.1, differential-
  fuzzing finding D5). automerge 0.12 reads such an author and aborts applying
  it on a later change; refusing it before the engine keeps the replica intact
  (a unit test covers the detection, the rule and the replica's recovery, and
  the shared sections corpus covers it as SS70).

### Changed

- `spec.lock` moves to `mvp-0.2-baseline.6` and `server.lock` to the matching
  server. baseline.6 bounds a change's sequence number and time below 2^53
  (§11.3 rule 2, finding D2), orders the checks of a change's bytes then its
  actor before its dependencies (§14.1), and refuses collaborative Text in any
  field a profile does not define (SHARED-SECTIONS-PROFILE-01 A5, finding D3).
  The shared sections corpus gains SS66 to SS75; this SDK already decided D2,
  D3 and the ordering, so only the D5 rule above is new code.

## 0.2.0-beta.1 — 2026-10-10

The first beta of the 0.2 line, published under the npm dist-tag `beta`;
`latest` stays on the 0.1.x releases until 0.2.0 is final. 0.2 adds the
Shared Sections profile (Working Draft) and the section-aware sync client
on top of the Shared Objects admission module, with status and receipt
reporting, and hardens the Automerge binding. APIs may still change before
0.2.0. The SDK is read at spec `mvp-0.2-baseline.4`.

### Added

- Betas: a tag `vX.Y.Z-beta.N` publishes under the npm dist-tag `beta`,
  leaving `latest` on the last final release (`scripts/dist-tag.mjs`, used
  by `release.yml` and `pnpm release:check`; the dry run names the
  dist-tag). A prerelease that is neither `beta.N` nor `rc.N` is refused.
- `@openlfcp/shared-objects/admission` (LFCP-02-085): the admission of
  SHARED-OBJECTS-PROFILE-01 §§7–18 as a module every inheriting profile
  shares (SHARED-SECTIONS-PROFILE-01 §2): the framing, the expansion,
  depth and Snapshot limits, the actor binding with the profile's domain
  (`deriveDomainActorId`, `checkChangeActor`) and the sequence admission
  with held changes (`admitBatch`, `admitChange`). The Shared Objects
  profile now runs on it; its behaviour and exports are unchanged.
- The reference rules of SHARED-OBJECTS-PROFILE-01 §11.4 now refuse, from
  the change bytes before the engine, an increment that does not name a
  counter put (R8), an Automerge mark (action 7, R9) and an operation that
  makes a table (action 6, R10); each is `INVALID_AUTOMERGE_BYTES`. R10
  keeps the D1 table-making change (see Fixed) from reaching the engine.
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

### Fixed

- A received change that makes an Automerge table (action 6) and writes
  into it no longer poisons a replica (differential-fuzzing defect D1).
  Automerge JS 3.5.0 panics applying such a change ("Obj … Missing from
  Index"), which before left the aborted change as the document's head: the
  replica could not take the actor's next change ("duplicate seq") and a
  reload failed. Two backstops cover it: admission refuses the change
  (§11.4 R10) before the engine, and if any change aborts in the engine the
  document is rolled back to the changes it held before the apply, so an
  aborted change never becomes a replica's state (`applyChecked`,
  `applyBatchChecked`, both now exported from `@openlfcp/shared-objects`).
  Both `SharedObjectsReplica` and `SectionReplica` are covered.

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
