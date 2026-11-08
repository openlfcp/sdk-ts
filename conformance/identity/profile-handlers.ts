// IDENTITY-PROFILE-TEST-VECTORS-01 handlers (IDENTITY-PROFILE-01 §12.2 ID-05,
// LFCP-04-409b): the exact changes and their framing; admission AI0 to AI5
// of every change against its causal history, with the writer class taken
// from the Control state of I at the unit's control_ref; per-entry state
// validation of §4 on the case's Snapshot; the replica scenarios (delivery
// orders, KEY_BLOCKED, Snapshots, refused changes and their dependants);
// pairing links, fingerprints, the approval digest and the rootOf tables.
//
// The replica is @openlfcp/shared-objects' IdentityReplica throughout: a
// change is delivered with its writer (signer, unit actor sequence, class)
// as a verified Data Unit would be, and the state is read from its save.

import { identityWriterClass, pairingLinkRejection, readersAt } from "@openlfcp/client";
import {
  bytesEqual,
  fromBase64url,
  fromHex,
  LfcpError,
  type PrincipalId,
  principalId,
  type ResourceId,
  resourceId,
  toHex,
} from "@openlfcp/core";
import { sha256 } from "@openlfcp/crypto";
import { checkChange, frameChange } from "@openlfcp/shared-objects/admission";
import {
  IDENTITY_DIAGNOSTIC_ORDER,
  type IdentityReceiveResult,
  IdentityReplica,
  type IdentityUnit,
  type IdentityWriterClass,
  validateIdentity,
} from "@openlfcp/shared-objects/identity";
import {
  activeDevice,
  actsFor,
  assemblePairingUri,
  decodeControlRecord,
  decodeInviteSecret,
  deviceFingerprint,
  encodeInviteSecret,
  invitationPrincipal,
  isBound,
  pairingDeviceSigner,
  parseDeviceCertificate,
  parseInviteUri,
  parsePairingUri,
  rootOf,
} from "@openlfcp/wire";
import { cborMap, encode } from "@openlfcp/wire/cbor";
import {
  identityView,
  withIdentityDocument,
} from "../../packages/shared-objects/test/support/identity-view.js";
import { bytesCheck, check, equalCheck, outcomeCheck } from "../checks.js";
import type { Check, Handler, HandlerContext, VectorCase } from "../runner.js";
import { chainAt, idOf, wire, wireCase } from "./corpus.js";

type Fields = Readonly<Record<string, unknown>> | undefined;
// biome-ignore lint/suspicious/noExplicitAny: corpus JSON
type Json = any;

function hexOf(fields: Fields, name: string): Uint8Array {
  const v = fields?.[name] as { hex?: unknown } | undefined;
  if (typeof v?.hex !== "string") throw new Error(`field ${name} is not a {hex} value`);
  return fromHex(v.hex);
}

interface Fixtures {
  readonly identity_resource: { readonly hex: string };
  readonly owner_ref: string;
}
const fixturesOf = (context: HandlerContext) => context.suite.fixtures as Fixtures;
const parseRef = (ref: string): PrincipalId => {
  if (!ref.startsWith("p:")) throw new Error(`not a PrincipalRef: ${ref}`);
  return principalId(fromBase64url(ref.slice(2)));
};
function optionsOf(context: HandlerContext): { resource: ResourceId; root: PrincipalId } {
  const f = fixturesOf(context);
  return { resource: resourceId(fromHex(f.identity_resource.hex)), root: parseRef(f.owner_ref) };
}

/** Where the corpus names a change: `change.<name>` or a validation case of its own. */
const changeCase = (context: HandlerContext, name: string): VectorCase => {
  const c = context.caseById(name.startsWith("change.") ? name : `change.${name}`);
  if (c === undefined) throw new Error(`no change case ${name}`);
  return c;
};
const changeBytes = (c: VectorCase): Uint8Array =>
  hexOf(
    c.inputs,
    c.inputs?.automerge_change_hex !== undefined ? "automerge_change_hex" : "automerge_change",
  );

/** The verified unit that carries a change case's bytes. */
function unitOf(c: VectorCase): IdentityUnit {
  const i = c.inputs as Json;
  return {
    bytes: changeBytes(c),
    signer: parseRef(i.writer_ref),
    actorSeq: BigInt(i.unit_actor_seq),
    writerClass: i.writer_class as IdentityWriterClass,
  };
}

/**
 * §2.3: the writer's class at the unit's control_ref, from the Control state
 * of I in LFCP-IDENTITY-TEST-VECTORS-01; it must be the class the case states.
 */
function writerClassCheck(name: string, c: VectorCase, context: HandlerContext): Check {
  const i = c.inputs as Json;
  return check(name, () => {
    const state = chainAt(i.control_ref).state;
    const got = identityWriterClass(state, optionsOf(context).root, parseRef(i.writer_ref));
    return (
      got === i.writer_class || `the class at ${i.control_ref} is ${got}, not ${i.writer_class}`
    );
  });
}

/** The change's own facts: its hash, actor, Automerge sequence and dependencies. */
function changeFactsCheck(name: string, c: VectorCase): Check {
  const i = c.inputs as Json;
  return check(name, () => {
    const change = checkChange(changeBytes(c));
    const deps = Array.isArray(i.deps) ? i.deps : i.deps === "" ? [] : String(i.deps).split(",");
    if (change.hash !== i.change_hash) return `hash ${change.hash}, not ${i.change_hash}`;
    if (change.actor !== i.automerge_actor)
      return `actor ${change.actor}, not ${i.automerge_actor}`;
    if (change.seq !== i.automerge_seq) return `seq ${change.seq}, not ${i.automerge_seq}`;
    return (
      equalCheck("deps", [...deps].sort(), [...change.deps].sort()).ok || "the dependencies differ"
    );
  });
}

// ---------------------------------------------------------------------------
// Replicas

interface Delivery {
  readonly admitted: readonly string[];
  /** The change hashes admitted, in admission order. */
  readonly admittedHashes: readonly string[];
  readonly refused: Readonly<Record<string, string>>;
  readonly held: readonly string[];
  readonly pending: readonly string[];
  readonly initial: string | null;
  readonly replica: IdentityReplica;
}

/**
 * Delivers the named changes one Data Unit at a time, in order; the units
 * named in `blocked` (KEY_BLOCKED, W §65) only after all the others.
 */
function deliver(
  context: HandlerContext,
  names: readonly string[],
  blocked: readonly string[] = [],
): Delivery {
  const byHash = new Map<string, string>();
  const replica = IdentityReplica.empty(optionsOf(context));
  const admitted: string[] = [];
  const admittedHashes: string[] = [];
  const refused: Record<string, string> = {};
  const held: string[] = [];
  let last: IdentityReceiveResult | undefined;
  const order = [...names.filter((n) => !blocked.includes(n)), ...blocked];
  for (const name of order) {
    const c = changeCase(context, name);
    byHash.set(String((c.inputs as Json).change_hash), name);
    last = replica.receiveChanges([unitOf(c)]);
    for (const h of last.admitted) {
      admitted.push(byHash.get(h) ?? h);
      admittedHashes.push(h);
    }
    for (const r of last.refused) {
      const n = r.hash === undefined ? name : (byHash.get(r.hash) ?? r.hash);
      if (r.held) held.push(n);
      else refused[n] = r.diagnostic;
    }
  }
  const pending = (last?.waiting ?? []).map((h) => byHash.get(h) ?? h);
  const initial = replica
    .changes()
    .map(checkChange)
    .find((ch) => ch.deps.length === 0);
  return {
    admitted,
    admittedHashes,
    refused,
    held,
    pending: [...pending].sort(),
    initial: initial === undefined ? null : (byHash.get(initial.hash) ?? initial.hash),
    replica,
  };
}

const sorted = (xs: readonly string[]) => [...xs].sort();
const nameOfChange = (context: HandlerContext, hash: string): string =>
  context.suite.cases
    .find((c) => c.id.startsWith("change.") && (c.inputs as Json).change_hash === hash)
    ?.id.slice(7) ?? hash;

/** The state a replica's save holds, as the corpus views it. */
const stateOf = (replica: IdentityReplica) => identityView(replica.save());

/** §4 per entry: "valid" or the entry's diagnostic, first in table order. */
function entryOutcome(
  problems: readonly { readonly diagnostic: string; readonly pointer: string }[],
  container: string,
  key: string,
): string {
  const base = `/${container}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`;
  const own = problems.filter((p) => p.pointer === base || p.pointer.startsWith(`${base}/`));
  const first = IDENTITY_DIAGNOSTIC_ORDER.find((d) => own.some((p) => p.diagnostic === d));
  return first ?? "valid";
}

function entriesOf(
  validation: { readonly problems: readonly { diagnostic: string; pointer: string }[] },
  expected: Readonly<Record<string, Readonly<Record<string, string>>>>,
): Record<string, Record<string, string>> {
  return Object.fromEntries(
    Object.entries(expected).map(([container, keys]) => [
      container,
      Object.fromEntries(
        Object.keys(keys).map((k) => [k, entryOutcome(validation.problems, container, k)]),
      ),
    ]),
  );
}

// ---------------------------------------------------------------------------
// reports (lfcp-identity-outcomes/1)

type Report = Record<string, unknown>;
const accepted = (ids: readonly string[], postState: unknown = null): Report => ({
  outcome: "accept",
  accepted_ids: [...ids],
  post_state: postState,
});
const refusedReport = (code: string, diagnostic: string | null, detail?: string): Report => ({
  outcome: code,
  diagnostic,
  ...(detail === undefined ? {} : { detail }),
  accepted_ids: [],
  post_state: null,
});

// ---------------------------------------------------------------------------
// bytes

const framing: Handler = (c) => {
  const framed = frameChange(changeBytes(c));
  const checks = [
    bytesCheck("framed_cbor", hexOf(c.expected, "framed_cbor"), framed),
    bytesCheck("sha256", hexOf(c.expected, "sha256"), sha256(framed)),
  ];
  if ((c.inputs as Json).change_hash !== undefined && (c.inputs as Json).deps !== undefined)
    checks.push(changeFactsCheck("framed_cbor/change", c));
  return { checks, report: accepted([checkChange(changeBytes(c)).hash]) };
};

/** The §18.2 secret of the inputs' keys, through the SDK's own decoder. */
const secretOf = (c: VectorCase) =>
  decodeInviteSecret(
    encode(
      cborMap([
        [0, 1n],
        [1, hexOf(c.inputs, "ed25519_seed")],
        [2, hexOf(c.inputs, "x25519_private")],
      ]),
    ),
  );

const pairUri: Handler = (c) => {
  const i = c.inputs as Json;
  const secret = secretOf(c);
  const device = invitationPrincipal(secret).principalId;
  return {
    checks: [
      bytesCheck("secret_cbor", hexOf(c.expected, "secret_cbor"), encodeInviteSecret(secret)),
      bytesCheck("recomputed_principal_id", hexOf(c.expected, "recomputed_principal_id"), device),
      check("recomputed_principal_id/input", () =>
        bytesEqual(device, hexOf(c.inputs, "pairing_device_id")),
      ),
      equalCheck(
        "uri",
        c.expected.uri,
        assemblePairingUri({
          identityResourceId: resourceId(hexOf(c.inputs, "identity_resource")),
          endpoints: [String(i.endpoint)],
          pairingDevice: device,
          secret,
        }),
      ),
      check("uri/parse", () => {
        const link = parsePairingUri(String(c.expected.uri));
        return (
          (bytesEqual(link.pairingDevice, device) &&
            bytesEqual(link.identityResourceId, hexOf(c.inputs, "identity_resource")) &&
            link.endpoints.length === 1 &&
            link.endpoints[0] === i.endpoint) ||
          "the parsed link differs"
        );
      }),
    ],
    report: accepted([toHex(device)]),
  };
};

const FP_DOMAIN = new TextEncoder().encode("LFCP-DEVICE-FP-v1");
const fingerprint: Handler = (c) => {
  const id = principalId(hexOf(c.inputs, "principal_id"));
  return {
    checks: [
      bytesCheck(
        "digest_prefix",
        hexOf(c.expected, "digest_prefix"),
        sha256(Uint8Array.from([...FP_DOMAIN, ...id])).subarray(0, 10),
      ),
      equalCheck("fingerprint", c.expected.fingerprint, deviceFingerprint(id)),
    ],
    report: accepted([], { fingerprint: deviceFingerprint(id) }),
  };
};

const approvalDigest: Handler = (c) => {
  const certificate = parseDeviceCertificate(hexOf(c.inputs, "cose_sign1"));
  const digest = certificate.payloadDigest;
  const consuming = String(c.expected.consuming_record);
  return {
    checks: [
      bytesCheck("payload_digest", hexOf(c.expected, "payload_digest"), digest),
      check("consuming_record", () => {
        const { body } = decodeControlRecord(fromHex(wireCase(consuming).inputs.cose_sign1.hex));
        return (
          (body.type === "DEVICE_REVOKE" &&
            body.reason === 3n &&
            body.approval !== undefined &&
            bytesEqual(body.approval, digest)) ||
          `${consuming} does not consume the approval of this certificate`
        );
      }),
      bytesCheck(
        "consuming_record_id",
        hexOf(c.expected, "consuming_record_id"),
        fromHex(wireCase(consuming).inputs.record_id.hex),
      ),
    ],
    report: accepted([toHex(certificate.id)], { payload_digest: toHex(digest) }),
  };
};

// ---------------------------------------------------------------------------
// validation

/** §3: a change against its causal history (every history change admitted first). */
const profileChange: Handler = (c, context) => {
  const i = c.inputs as Json;
  const history = ((c.context as Json)?.history ?? []) as { case: string }[];
  const replica = IdentityReplica.empty(optionsOf(context));
  const admitted: string[] = [];
  const checks: Check[] = [
    writerClassCheck("outcome/writer_class", c, context),
    changeFactsCheck("outcome/change", c),
  ];
  for (const h of history) {
    const r = replica.receiveChanges([unitOf(changeCase(context, h.case))]);
    admitted.push(...r.admitted);
    if (r.admitted.length === 0)
      return {
        checks: [
          ...checks,
          { name: "outcome", ok: false, message: `history change ${h.case} is not admitted` },
        ],
      };
  }
  const result = replica.receiveChanges([unitOf(c)]);
  const refusal = result.refused[0];
  const expected = c.expected as Json;
  // accepted_ids: every change the replica admitted, its history included.
  const report: Report = result.admitted.includes(i.change_hash)
    ? accepted([...new Set([...admitted, ...result.admitted])].sort(), stateOf(replica))
    : refusal === undefined
      ? { outcome: "waiting", accepted_ids: [], post_state: null }
      : refusedReport(refusal.code, refusal.diagnostic, refusal.message);
  if (expected.valid === true)
    checks.push(
      check(
        "outcome",
        () =>
          result.admitted.includes(i.change_hash) ||
          (refusal === undefined
            ? "the change is not admitted: it waits"
            : `refused: ${refusal.code} ${refusal.diagnostic} (${refusal.message})`),
      ),
    );
  else {
    checks.push(outcomeCheck("outcome", expected.error.code, refusal?.code ?? null));
    checks.push(
      equalCheck("outcome/diagnostic", expected.error.diagnostic, refusal?.diagnostic ?? null),
    );
  }
  return { checks, report };
};

/** §4 on the case's Snapshot: the entry, then its outcome. */
const profileEntry: Handler = (c, context) => {
  const i = c.inputs as Json;
  const save = fromBase64url(i.snapshot.b64url);
  const view = identityView(save) as Json;
  const { root } = optionsOf(context);
  const outcome = withIdentityDocument(save, (doc) =>
    entryOutcome(validateIdentity(doc, root).problems, i.container, i.key),
  );
  const conflicted = `${i.key}_conflict_set`;
  const checks: Check[] = [
    equalCheck(
      "outcome/entry",
      i.entry,
      Object.hasOwn(view[i.container], conflicted)
        ? { [conflicted]: view[i.container][conflicted] }
        : view[i.container][i.key],
    ),
  ];
  if (i.fingerprint !== undefined)
    checks.push(
      equalCheck("outcome/fingerprint", i.fingerprint, deviceFingerprint(parseRef(i.key))),
    );
  const expected = c.expected as Json;
  const isConflicted = Object.hasOwn(view[i.container], conflicted);
  const report: Report =
    outcome === "valid"
      ? accepted([], view[i.container][i.key] ?? null)
      : refusedReport(
          "PROFILE_INVALID",
          outcome,
          isConflicted ? "conflicted entry (§4 rule 2)" : undefined,
        );
  if (expected.valid === true) checks.push(equalCheck("outcome", "valid", outcome));
  else {
    checks.push(
      outcomeCheck("outcome", expected.error.code, outcome === "valid" ? null : "PROFILE_INVALID"),
    );
    checks.push(equalCheck("outcome/diagnostic", expected.error.diagnostic, outcome));
  }
  return { checks, report };
};

/**
 * §5.2: a rejected link is a client-local outcome with no wire code (W §62);
 * the corpora name it PAIRING_LINK_REJECTED. The SDK rejects it with the
 * client-local INVALID_INVITATION, which is never sent.
 */
/**
 * §5.2 checks 2–4 with sdk-ts's pairingLinkRejection, on the Identity
 * Resource as the case's `binding_head` leaves it. The coordinator's side of
 * check 2 (W §41: a session is opened only by a reader) is the fixture's;
 * the client's side is what it does with that refusal.
 */
function linkRejection(i: Json): string | undefined {
  const J = pairingDeviceSigner(parsePairingUri(String(i.uri))).descriptor.principalId;
  const chain = chainAt(String(i.binding_head));
  const reader = readersAt(chain.state).some((r) => bytesEqual(r.principalId, J));
  return pairingLinkRejection(J, reader ? chain : { refused: "AUTHORIZATION_FAILED" });
}
/** The link's device, accepted when every check passes (as a pair_uri bytes case reports it). */
const linkDevice = (i: Json): PrincipalId =>
  pairingDeviceSigner(parsePairingUri(String(i.uri))).descriptor.principalId;

const pairUriRejected: Handler = (c) => {
  const i = c.inputs as Json;
  let code: string | null = null;
  try {
    if (i.parser === "join") parseInviteUri(String(i.uri));
    else if (i.parser === "pair") {
      parsePairingUri(String(i.uri));
      if (i.binding_head !== undefined && linkRejection(i) !== undefined)
        throw new LfcpError("INVALID_INVITATION", "the pairing link is rejected (§5.2)");
    } else throw new Error(`unknown parser ${i.parser}`);
  } catch (e) {
    code =
      e instanceof LfcpError && e.code === "INVALID_INVITATION"
        ? "PAIRING_LINK_REJECTED"
        : String(e);
  }
  const expected = c.expected as Json;
  return {
    checks: [
      expected.valid === false
        ? outcomeCheck("outcome", expected.error.code, code)
        : equalCheck("outcome", null, code),
    ],
    report:
      code === null
        ? accepted(i.binding_head === undefined ? [] : [toHex(linkDevice(i))])
        : refusedReport(code, null, code === "PAIRING_LINK_REJECTED" ? undefined : code),
  };
};

// ---------------------------------------------------------------------------
// behavioral

/**
 * A scenario's checks, and its report: `post` is the state it derived in
 * the corpus's shape (from the first delivery order when there are several;
 * the checks require every order to agree), `runs` every delivery it made.
 */
interface ScenarioResult {
  readonly checks: Check[];
  readonly post: Json;
  readonly runs: readonly Delivery[];
}
type Scenario = (c: VectorCase, context: HandlerContext) => ScenarioResult;

const namesOf = (refs: readonly { case: string }[]) =>
  refs.map((r) => r.case.replace(/^change\./, ""));
const unitsOf = (context: HandlerContext, names: readonly string[]) =>
  names.map((n) => unitOf(changeCase(context, n)));

/** The replica from a Snapshot and the verified units of its changes (§2.2). */
function fromSnapshot(
  context: HandlerContext,
  b64url: string,
  names: readonly string[],
): IdentityReplica | Error {
  try {
    return IdentityReplica.fromSave(
      fromBase64url(b64url),
      optionsOf(context),
      unitsOf(context, names),
    );
  } catch (e) {
    return e instanceof Error ? e : new Error(String(e));
  }
}

/**
 * §4 on a Snapshot whose initial change holds a container as a list (the
 * change itself is refused by AI0): loaded as a state and validated, the
 * root is INVALID_ROOT and the document is not usable.
 */
const initialListSnapshot: Scenario = (c, context) => {
  const i = c.inputs as Json;
  const e = c.expected as Json;
  const { root } = optionsOf(context);
  const validation = withIdentityDocument(fromBase64url(i.snapshot.b64url), (doc) =>
    validateIdentity(doc, root),
  );
  const rootProblem = validation.problems.find((p) => p.diagnostic === "INVALID_ROOT");
  const post = {
    root_diagnostic: rootProblem?.diagnostic ?? null,
    document_usable: validation.usable,
  };
  return {
    checks: [
      equalCheck("root_diagnostic", e.root_diagnostic, post.root_diagnostic),
      equalCheck("document_usable", e.document_usable, post.document_usable),
    ],
    post,
    runs: [],
  };
};

const SCENARIOS: Readonly<Record<string, Scenario>> = {
  ...Object.fromEntries(
    ["roster", "devices", "requests", "extensions"].map((t) => [
      `identity_doc_initial_${t}_list.snapshot`,
      initialListSnapshot,
    ]),
  ),
  identity_doc_second_initial_other_unit: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const checks: Check[] = [];
    const runs: Delivery[] = [];
    const byOrder: Record<string, Json> = {};
    for (const [k, order] of Object.entries(i.orders as Record<string, Json>)) {
      const run = Array.isArray(order)
        ? deliver(context, order)
        : deliver(context, order.order, order.key_blocked_until_end);
      runs.push(run);
      byOrder[k] = {
        initial_change: run.initial,
        refused: run.refused,
        held: run.held,
        pending: run.pending,
      };
      checks.push(equalCheck(`by_order/${k}`, e.by_order[k], byOrder[k]));
    }
    const snap = fromSnapshot(context, i.snapshot.b64url, [i.snapshot.carries]);
    const snapshot = {
      initial_change:
        snap instanceof Error
          ? null
          : nameOfChange(
              context,
              snap
                .changes()
                .map(checkChange)
                .find((x) => x.deps.length === 0)?.hash ?? "",
            ),
      used: !(snap instanceof Error),
    };
    checks.push(equalCheck("snapshot", e.snapshot, snapshot));
    return { checks, post: { by_order: byOrder, snapshot }, runs };
  },

  identity_doc_initial_without_unit_1: (c, context) => {
    const i = c.inputs as Json;
    const unit1 = i.root_unit_1.case.replace(/^change\./, "");
    const snap = fromSnapshot(context, i.snapshot.b64url, [unit1]);
    const run = deliver(context, [unit1]);
    const post = { snapshot_used: !(snap instanceof Error), initial_change: run.initial };
    const checks = [
      equalCheck("snapshot_used", c.expected.snapshot_used, post.snapshot_used),
      check(
        "snapshot_used/hash",
        () =>
          // The Snapshot's change without dependencies is the one the case names, not unit 1's.
          snapshotInitial(i.snapshot.b64url) === i.snapshot_initial_change_hash &&
          snapshotInitial(i.snapshot.b64url) !==
            (changeCase(context, unit1).inputs as Json).change_hash,
      ),
      equalCheck("initial_change", c.expected.initial_change, run.initial),
    ];
    return { checks, post, runs: [run] };
  },

  identity_doc_initial_then_fill: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const checks: Check[] = [];
    const runs: Delivery[] = [];
    let post: Json;
    const names = namesOf(i.changes);
    for (const order of i.orders as string[][]) {
      const run = deliver(context, order);
      runs.push(run);
      const at = order.join(",");
      const validation = run.replica.validate();
      post ??= {
        admitted: sorted(run.admitted),
        entries: entriesOf(validation, e.entries),
        root_valid: validation.usable,
        state: stateOf(run.replica),
      };
      checks.push(
        equalCheck(`state/${at}`, e.state, stateOf(run.replica)),
        equalCheck(`root_valid/${at}`, e.root_valid, validation.usable),
        equalCheck(`admitted/${at}`, sorted(e.admitted), sorted(run.admitted)),
        equalCheck(`entries/${at}`, e.entries, entriesOf(validation, e.entries)),
      );
    }
    const snap = fromSnapshot(context, i.snapshot.b64url, names);
    checks.push(
      check("state/snapshot", () =>
        snap instanceof Error
          ? `the Snapshot is not used: ${snap.message}`
          : equalCheck("state", e.state, stateOf(snap)).ok || "the Snapshot's state differs",
      ),
    );
    return { checks, post, runs };
  },

  pairing_concurrent_same_key: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const history = namesOf(i.history);
    const changes = namesOf(i.changes);
    const checks: Check[] = [];
    const runs: Delivery[] = [];
    let post: Json;
    for (const order of [changes, [...changes].reverse()]) {
      const run = deliver(context, [...history, ...order]);
      runs.push(run);
      const at = order.join(",");
      const view = stateOf(run.replica) as Json;
      const validation = run.replica.validate();
      const outcome = entryOutcome(validation.problems, "requests", e.entry);
      post ??= {
        admitted: sorted(run.admitted.filter((n) => changes.includes(n))),
        entry: e.entry,
        entry_conflicted: Object.hasOwn(view.requests, `${e.entry}_conflict_set`),
        entry_diagnostic: outcome,
        entry_valid: outcome === "valid" && Object.hasOwn(validation.requests, e.entry),
      };
      checks.push(
        equalCheck(
          `admitted/${at}`,
          sorted(e.admitted),
          sorted(run.admitted.filter((n) => changes.includes(n))),
        ),
        check(
          `entry/${at}`,
          () =>
            Object.hasOwn(view.requests, e.entry) ||
            Object.hasOwn(view.requests, `${e.entry}_conflict_set`),
        ),
        equalCheck(
          `entry_conflicted/${at}`,
          e.entry_conflicted,
          Object.hasOwn(view.requests, `${e.entry}_conflict_set`),
        ),
        equalCheck(
          `entry_valid/${at}`,
          e.entry_valid,
          outcome === "valid" && Object.hasOwn(validation.requests, e.entry),
        ),
        equalCheck(`entry_diagnostic/${at}`, e.entry_diagnostic, outcome),
      );
    }
    return { checks, post, runs };
  },

  device_entry_missing_keys_union: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const save = fromBase64url(i.snapshot.b64url);
    const view = identityView(save) as Json;
    const { root } = optionsOf(context);
    const key = Object.keys(view.devices).find(
      (k) => view.devices[k].missing_keys_conflict_set !== undefined,
    );
    if (key === undefined)
      return {
        checks: [
          { name: "entry_valid", ok: false, message: "no entry with a missing_keys conflict" },
        ],
        post: null,
        runs: [],
      };
    const validation = withIdentityDocument(save, (doc) => validateIdentity(doc, root));
    const read = validation.devices[key]?.missing_keys;
    const post = {
      entry_valid: entryOutcome(validation.problems, "devices", key) === "valid",
      missing_keys_conflict_set: view.devices[key].missing_keys_conflict_set,
      missing_keys_read:
        read === undefined
          ? null
          : Object.fromEntries(Object.entries(read).map(([r, eps]) => [r, eps.map(Number)])),
    };
    const checks = [
      check("entry_valid/changes", () => {
        const hashes = new Set(snapshotHashes(i.snapshot.b64url));
        return namesOf(i.changes).every((n) =>
          hashes.has((changeCase(context, n).inputs as Json).change_hash),
        );
      }),
      equalCheck("entry_valid", e.entry_valid, post.entry_valid),
      equalCheck(
        "missing_keys_conflict_set",
        e.missing_keys_conflict_set,
        post.missing_keys_conflict_set,
      ),
      equalCheck("missing_keys_read", e.missing_keys_read, post.missing_keys_read),
    ];
    return { checks, post, runs: [] };
  },

  missing_keys_concurrent_device_and_root: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const checks: Check[] = [];
    const runs: Delivery[] = [];
    let post: Json;
    for (const [k, order] of Object.entries(i.orders as Record<string, string[]>)) {
      const run = deliver(context, order);
      runs.push(run);
      checks.push(...deliveryChecks(k, e, run));
      const view = stateOf(run.replica) as Json;
      const entry = view.devices[e.state.entry];
      const validation = run.replica.validate();
      const read = validation.devices[e.state.entry]?.missing_keys;
      const state = {
        entry: e.state.entry,
        entry_valid: entryOutcome(validation.problems, "devices", e.state.entry) === "valid",
        missing_keys_conflict_set:
          entry?.missing_keys_conflict_set ??
          (entry?.missing_keys === undefined ? [] : [entry.missing_keys]),
        missing_keys_read:
          read === undefined
            ? null
            : Object.fromEntries(Object.entries(read).map(([r, eps]) => [r, eps.map(Number)])),
      };
      post ??= { ...deliveryOf(context, run), state };
      checks.push(equalCheck(`state/${k}`, e.state, state));
    }
    return { checks, post, runs };
  },

  missing_keys_hidden_entry_resolution: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const checks: Check[] = [];
    const runs: Delivery[] = [];
    const post: Json = {};
    for (const [k, order] of Object.entries(i.orders as Record<string, string[]>)) {
      const run = deliver(context, order);
      runs.push(run);
      post[k] = { ...deliveryOf(context, run), state: stateOf(run.replica) };
      checks.push(...deliveryChecks(k, e[k], run).map((x) => ({ ...x, name: `${k}/${x.name}` })));
      checks.push(equalCheck(`${k}/state`, e[k].state, post[k].state));
    }
    return { checks, post, runs };
  },

  identity_snapshot_equivalence: (c, context) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const names = namesOf(i.changes);
    const run = deliver(context, names);
    const validation = run.replica.validate();
    const snap = fromSnapshot(context, i.snapshot.b64url, names);
    const post = {
      entries: entriesOf(validation, e.entries),
      root_valid: validation.usable,
      state: stateOf(run.replica),
    };
    const checks = [
      equalCheck("state", e.state, stateOf(run.replica)),
      equalCheck("root_valid", e.root_valid, validation.usable),
      equalCheck("entries", e.entries, entriesOf(validation, e.entries)),
      check("state/snapshot", () =>
        snap instanceof Error
          ? `the Snapshot is not used: ${snap.message}`
          : equalCheck("state", e.state, stateOf(snap)).ok || "the Snapshot's state differs",
      ),
      check("entries/snapshot", () =>
        snap instanceof Error
          ? `the Snapshot is not used: ${snap.message}`
          : equalCheck("entries", e.entries, entriesOf(snap.validate(), e.entries)).ok ||
            "the Snapshot's entries differ",
      ),
    ];
    return { checks, post, runs: [run] };
  },

  root_of_corpus: (c) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const post: Json = {};
    const checks = Object.entries(i.heads as Record<string, string>).map(([name, head]) =>
      check(name, () => {
        const state = chainAt(head).state;
        const table = e[name] as Record<string, Json>;
        const labelOf = (id: PrincipalId) =>
          Object.keys(table).find((l) => bytesEqual(idOf(l), id)) ?? toHex(id);
        const got = Object.fromEntries(
          Object.keys(table).map((label) => {
            const p = idOf(label);
            return [
              label,
              {
                rootOf: labelOf(rootOf(state, p)),
                actsFor: labelOf(actsFor(state, p)),
                bound: isBound(state, p),
                active: activeDevice(state, p) !== undefined,
              },
            ];
          }),
        );
        post[name] = got;
        const r = equalCheck(name, table, got);
        return r.ok || r.message;
      }),
    );
    return { checks, post, runs: [] };
  },

  assignee_root_ref: (c) => {
    const i = c.inputs as Json;
    const e = c.expected as Json;
    const state = chainAt(i.head).state;
    const assignees = i.assignees as string[];
    const labels = (wire.cases.filter((x) => x.kind === "principal") as Json[]).map(
      (x) => x.inputs.label as string,
    );
    const labelOf = (id: PrincipalId) => labels.find((l) => bytesEqual(idOf(l), id)) ?? toHex(id);
    // Assignees are stored as given (a set of PrincipalRefs) and merged by rootOf in display only.
    const humans = new Map<string, string[]>();
    for (const ref of assignees) {
      const human = labelOf(rootOf(state, parseRef(ref)));
      humans.set(human, [...(humans.get(human) ?? []), ref]);
    }
    const post = {
      crdt_set: [...new Set(assignees)].sort(),
      display_humans: [...humans.keys()],
      merged: Object.fromEntries(
        [...humans].filter(([, refs]) => refs.length > 1).map(([h, refs]) => [h, sorted(refs)]),
      ),
    };
    const checks = [
      equalCheck("crdt_set", e.crdt_set, post.crdt_set),
      equalCheck("display_humans", e.display_humans, post.display_humans),
      equalCheck("merged", e.merged, post.merged),
    ];
    return { checks, post, runs: [] };
  },
};

/** A delivery in the corpus's shape: admitted, refused (code and diagnostic) and pending names. */
function deliveryOf(context: HandlerContext, run: Delivery): Json {
  void context;
  return {
    admitted: run.admitted,
    pending: run.pending,
    refused: Object.fromEntries(
      Object.entries(run.refused).map(([k, d]) => [k, { code: "PROFILE_INVALID", diagnostic: d }]),
    ),
  };
}

function deliveryChecks(name: string, e: Json, run: Delivery): Check[] {
  return [
    equalCheck(`admitted/${name}`, sorted(e.admitted), sorted(run.admitted)),
    equalCheck(
      `refused/${name}`,
      Object.fromEntries(
        Object.entries(e.refused as Record<string, Json>).map(([k, v]) => [k, v.diagnostic]),
      ),
      run.refused,
    ),
    equalCheck(`pending/${name}`, sorted(e.pending), run.pending),
    equalCheck(`pending/${name}/held`, [], run.held),
  ];
}

function snapshotHashes(b64url: string): string[] {
  return withIdentityDocument(fromBase64url(b64url), (_doc, changes) =>
    changes.map((b) => checkChange(b).hash),
  );
}
const snapshotInitial = (b64url: string): string | undefined =>
  withIdentityDocument(
    fromBase64url(b64url),
    (_doc, changes) => changes.map(checkChange).find((x) => x.deps.length === 0)?.hash,
  );

const identityDocument: Handler = (c, context) => {
  const scenario = Object.hasOwn(SCENARIOS, c.id) ? SCENARIOS[c.id] : undefined;
  if (scenario === undefined) throw new Error(`no scenario for ${c.id}`);
  const r = scenario(c, context);
  // accepted_ids: the changes the first delivery admitted (every order admits a set the checks compare).
  const ids = [...new Set(r.runs[0]?.admittedHashes ?? [])].sort();
  return { checks: r.checks, report: accepted(ids, r.post) };
};

export const IDENTITY_PROFILE_HANDLERS: Readonly<Record<string, Handler>> = {
  "bytes/profile_change_framing": framing,
  "bytes/pair_uri": pairUri,
  "bytes/device_fingerprint": fingerprint,
  "bytes/approval_digest": approvalDigest,
  "validation/profile_change": profileChange,
  "validation/profile_entry": profileEntry,
  "validation/pair_uri": pairUriRejected,
  "behavioral/identity_document": identityDocument,
};
