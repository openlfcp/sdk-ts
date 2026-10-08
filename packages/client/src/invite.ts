import {
  bytesEqual,
  type ControlRecordId,
  type DataEpoch,
  type Hash32,
  hash32,
  LfcpError,
  type LfcpErrorCode,
  type ResourceId,
  toHex,
} from "@openlfcp/core";
import {
  type AgreementKeyPair,
  dekCommitment,
  exportSecretKeyBytes,
  InvitationSecret,
  type ResourceDEK,
} from "@openlfcp/crypto";
import { dekSecretRef, type LfcpStorage, type SecretStore } from "@openlfcp/storage";
import {
  ABILITY,
  type AnyMessage,
  assembleInviteUri,
  type ChainResult,
  type ControlHeadRef,
  createMessage,
  ERROR_CODE,
  invitationPrincipal,
  type LfcpMessage,
  type PrincipalDescriptor,
  parseControlRecord,
  parseInviteUri,
  parseKeyPackage,
  receiveKeyPackage,
  type Signer,
  sealKeyPackage,
  signControlRecord,
  validateControlChain,
  verifyInvitationSecret,
  verifyKeyPackage,
} from "@openlfcp/wire";
import { LfcpConnection, type WebSocketFactory } from "./connection.js";
import { queueControlRecord, queueKeyPackage } from "./queue.js";
import { loadControlChain, saveControlChain } from "./storage.js";

/**
 * Link invitations and the one-time capability claim (LFCP-WIRE-01 §18,
 * §18.1, §18.2, §25.2, §73; LFCP-053), built on the invitation codec of
 * @openlfcp/wire (LFCP-039b) and this package's queue and storage.
 *
 * - createInvitation (the inviter): a fresh Invitation Principal, a
 *   CAPABILITY_GRANT to it with an explicit claim_limit (a grant without
 *   one is not claimable, §18), and a Key Package of the current epoch's
 *   DEK sealed to it at the grant's head, both checked locally and queued
 *   for the coordinator; and the bearer lfcp://join link.
 * - acceptInvitation (the joiner), in the order of §73: authenticate and
 *   open the Resource as the Invitation Principal, fetch the Control
 *   Chain, verify that the secret's Principal is the grant's subject
 *   (§18.2) before the secret is used for anything else, open the
 *   invitation Key Package for the DEK (§25.2: the invitation exception),
 *   and submit a CAPABILITY_CLAIM signed by the Invitation Principal with
 *   CONTROL_PUT at the current head (§47). The coordinator serializes
 *   claims (§18.1 rule 6, §18.3): a claim that loses gets
 *   CONTROL_HEAD_MISMATCH, is rebuilt once on the refreshed chain, and the
 *   coordinator's answer to that is final (AUTHORIZATION_FAILED once the
 *   invitation is used up). The client does not pre-judge claimability:
 *   the coordinator is the serialization point.
 *
 * After a successful claim the claimant's storage holds the validated
 * chain with its new grant and the secrets hold the epoch's DEK, so a
 * SyncClient for the claimant opens and synchronizes the Resource as the
 * claimant. §73 delivers the DEK through the Invitation Principal's
 * package and draws no package to the claimant, so none is needed to
 * join; later epochs reach the claimant like any holder of data/read.
 *
 * Secrets: a bearer link is a key. InvitationLink and InvitationSecret
 * print "[redacted]"; nothing here logs; no error or result carries a
 * URI, a secret or a DEK.
 */

/** A bearer invitation URI, redacted when printed or serialized; reveal() is the only way to read it. */
export class InvitationLink {
  readonly #uri: string;

  constructor(uri: string) {
    this.#uri = uri;
  }

  /** The lfcp://join URI with its #secret= fragment. Hand it to the invitee only; never log it. */
  reveal(): string {
    return this.#uri;
  }

  toJSON(): string {
    return "[redacted]";
  }

  toString(): string {
    return "[redacted]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[redacted]";
  }
}

/** The usual invitation grant (§18): data/read, data/write, invite/claim. */
export const DEFAULT_INVITATION_ABILITIES: readonly bigint[] = Object.freeze([
  ABILITY.DATA_READ,
  ABILITY.DATA_WRITE,
  ABILITY.INVITE_CLAIM,
]);

const fail = (code: LfcpErrorCode, why: string): never => {
  throw new LfcpError(code, why);
};

type Linear = Extract<ChainResult, { kind: "linear" }>;

export interface CreateInvitationOptions {
  readonly storage: Pick<LfcpStorage, "control" | "commit">;
  readonly resourceId: ResourceId;
  /** The issuer: needs the authority to grant the abilities (§17.2) and key/distribute (§25.2). */
  readonly inviter: Signer;
  /** The DEK of the current Data Epoch; checked against the epoch's commitment. */
  readonly dek: ResourceDEK;
  /** The endpoint URLs the link names (§18.2), in order; at least one. */
  readonly endpoints: readonly string[];
  /** Must include invite/claim; default data/read, data/write, invite/claim. */
  readonly abilities?: readonly bigint[];
  /** How many claims the grant allows; default 1, at least 1. */
  readonly claimLimit?: bigint;
  readonly delegable?: readonly bigint[];
  /** The Invitation Principal; default a fresh one. */
  readonly secret?: InvitationSecret;
}

export interface CreatedInvitation {
  readonly link: InvitationLink;
  /** The invitation grant's Control Record ID, queued for CONTROL_PUT. */
  readonly grantId: ControlRecordId;
  readonly invitationPrincipal: PrincipalDescriptor;
  /** The queued Key Package of the current epoch, sealed to the Invitation Principal. */
  readonly keyPackageId: Hash32;
  readonly epoch: DataEpoch;
}

/**
 * The inviter's side (§18, §73). The grant must validate on the stored
 * chain and the package must pass §25.2 at the grant's head, both checked
 * before anything is queued; the grant is queued before the package.
 * Share the link once both are ACKed: until then the grant is not on the
 * coordinator's chain.
 */
export async function createInvitation(
  options: CreateInvitationOptions,
): Promise<CreatedInvitation> {
  const R = options.resourceId;
  const stored = await loadControlChain(options.storage, R);
  const view: Linear =
    stored?.kind === "linear"
      ? stored
      : fail("MISSING_DEPENDENCY", "no valid local Control Chain for the Resource");
  const abilities = options.abilities ?? DEFAULT_INVITATION_ABILITIES;
  const claimLimit = options.claimLimit ?? 1n;
  if (!abilities.includes(ABILITY.INVITE_CLAIM))
    fail("UNSUPPORTED_VALUE", "an invitation grant must include invite/claim (§18)");
  if (claimLimit < 1n)
    fail("UNSUPPORTED_VALUE", "an invitation grant needs a claim_limit of at least 1 (§18)");
  const epoch = view.state.epoch.epoch;
  if (!bytesEqual(dekCommitment(R, epoch, options.dek), view.state.epoch.dekCommitment))
    fail("DEK_COMMITMENT_MISMATCH", `the DEK is not the one committed for epoch ${epoch}`);

  const secret = options.secret ?? InvitationSecret.generate();
  const invitee = invitationPrincipal(secret);
  const grant = signControlRecord(
    { resourceId: R, controlSeq: view.state.seq + 1n, prevControlId: view.state.head },
    {
      type: "CAPABILITY_GRANT",
      subject: invitee,
      abilities,
      delegable: options.delegable ?? [],
      claimLimit,
    },
    options.inviter,
  );
  const extended = validateControlChain([...view.records.map((r) => r.signed.bytes), grant.bytes]);
  const next: Linear =
    extended.kind === "linear"
      ? extended
      : fail("AUTHORIZATION_FAILED", "the invitation grant does not validate on the local chain");
  const sealed = await sealKeyPackage({
    resourceId: R,
    epoch,
    controlHead: grant.recordId,
    recipient: invitee,
    dek: options.dek,
    signer: options.inviter,
  });
  const check = verifyKeyPackage(next, parseKeyPackage(sealed.bytes));
  if (check.kind !== "authorized")
    fail("AUTHORIZATION_FAILED", `the invitation Key Package is refused: ${check.message}`);
  await queueControlRecord(options.storage, grant.bytes);
  const keyPackageId = await queueKeyPackage(options.storage, sealed.bytes);
  const uri = assembleInviteUri({
    resourceId: R,
    endpoints: options.endpoints,
    grantId: grant.recordId,
    secret,
  });
  return Object.freeze({
    link: new InvitationLink(uri),
    grantId: grant.recordId,
    invitationPrincipal: invitee,
    keyPackageId,
    epoch,
  });
}

export interface AcceptInvitationOptions {
  /** The bearer link: an InvitationLink, or its revealed URI. */
  readonly link: InvitationLink | string;
  /** The claimant: receives the grant and later synchronizes as itself. */
  readonly claimant: { readonly signer: Signer; readonly agreement: AgreementKeyPair };
  /** The claimant's storage and secrets: on "claimed" they hold the chain and the DEK. */
  readonly storage: Pick<LfcpStorage, "control" | "commit">;
  readonly secrets: SecretStore;
  /** Abilities to claim; default the grant's, without invite/claim unless it is delegable (§18.1 rule 4). */
  readonly abilities?: readonly bigint[];
  /**
   * The Data Profiles the caller can open (§27). When given, the Resource's
   * Genesis profile must be one of them: otherwise the join stops with
   * "profile-unsupported" before the Key Package is fetched and before the
   * claim, so the invitation stays unused. Default: no check.
   */
  readonly dataProfiles?: readonly string[];
  /** The endpoint to use; default the link's first. */
  readonly url?: string;
  readonly now: () => number;
  readonly webSocket?: WebSocketFactory;
  /** When it settles, the attempt gives up: the caller's timer (e.g. a 30 s sleep). */
  readonly timeout?: Promise<unknown>;
  /**
   * Called as each §73 step starts, for a join dialog. The payload names
   * the step only: never a link, a secret, a key or a DEK. Synchronizing
   * comes after: a SyncClient for the claimant does it.
   */
  readonly onProgress?: (progress: AcceptInvitationProgress) => void;
}

/** The §73 steps of acceptInvitation, in order. */
export type AcceptInvitationStage =
  | "connecting"
  | "validating-invitation"
  | "retrieving-key"
  | "claiming-capability";

export interface AcceptInvitationProgress {
  readonly stage: AcceptInvitationStage;
  /** "claiming-capability" only: 1, or 2 when the claim is rebuilt after CONTROL_HEAD_MISMATCH. */
  readonly attempt?: number;
}

export type AcceptedInvitation =
  | {
      readonly kind: "claimed";
      readonly resourceId: ResourceId;
      /** The claimant's grant: the claim record's ID (§17.2, §18.1). */
      readonly grantId: ControlRecordId;
      readonly abilities: readonly bigint[];
      /** The epochs whose DEK the claimant now holds. */
      readonly epochs: readonly DataEpoch[];
      /** The CONTROL_PUT answers in order, e.g. ["ACK"] or ["CONTROL_HEAD_MISMATCH", "ACK"]. */
      readonly attempts: readonly string[];
    }
  | {
      /** The coordinator refused the claim, e.g. AUTHORIZATION_FAILED: the invitation is used up. */
      readonly kind: "refused";
      readonly resourceId: ResourceId;
      readonly code: string;
      readonly attempts: readonly string[];
    }
  | {
      /**
       * The Resource's Data Profile is not in the caller's dataProfiles: no
       * Key Package was fetched, no claim was made and nothing was stored,
       * so the invitation can still be used by a client that implements it.
       */
      readonly kind: "profile-unsupported";
      readonly resourceId: ResourceId;
      readonly code: "PROFILE_UNSUPPORTED";
      /** The Resource's Data Profile, from its Genesis. */
      readonly dataProfile: string;
    }
  | {
      /**
       * The claim could not be attempted or answered: the connection failed
       * or timed out, the server refused the session or a request, or the
       * chain is forked (§42: no security-sensitive mutation then).
       */
      readonly kind: "unavailable";
      readonly resourceId: ResourceId;
      readonly reason: string;
    };

const CODE_NAME = new Map<bigint, string>(Object.entries(ERROR_CODE).map(([k, v]) => [v, k]));
const codeName = (code: bigint): string => CODE_NAME.get(code) ?? `ERROR_${code}`;
const UINT64_MAX = 2n ** 64n - 1n;

/** Thrown inside the claim session for a transport or server-side stop; becomes "unavailable". */
class Unavailable extends Error {}

/** Request/response over one LfcpConnection, for the short session as the Invitation Principal. */
class ClaimSession {
  readonly #connection: LfcpConnection;
  readonly #inbox: AnyMessage[] = [];
  #waiters: (() => void)[] = [];
  #closed: string | null = null;
  #ready = false;
  #timedOut = false;

  constructor(
    options: { url: string; signer: Signer; now: () => number; webSocket?: WebSocketFactory },
    timeout: Promise<unknown>,
  ) {
    this.#connection = new LfcpConnection(options, {
      state: () => undefined,
      ready: () => {
        this.#ready = true;
        this.#wake();
      },
      message: (m) => {
        this.#inbox.push(m);
        this.#wake();
      },
      closed: (reason) => {
        this.#closed = reason;
        this.#wake();
      },
    });
    timeout.then(
      () => {
        this.#timedOut = true;
        this.#wake();
      },
      () => undefined,
    );
  }

  #wake(): void {
    const waiting = this.#waiters;
    this.#waiters = [];
    for (const w of waiting) w();
  }

  async #until<T>(take: () => T | undefined, what: string): Promise<T> {
    for (;;) {
      const v = take();
      if (v !== undefined) return v;
      if (this.#timedOut) throw new Unavailable(`timed out waiting for ${what}`);
      if (this.#closed !== null)
        throw new Unavailable(`the connection closed while waiting for ${what}: ${this.#closed}`);
      await new Promise<void>((r) => this.#waiters.push(r));
    }
  }

  async connect(): Promise<void> {
    this.#connection.connect();
    await this.#until(() => (this.#ready ? true : undefined), "READY");
  }

  /** Sends a request and returns a function awaiting its next correlated reply. */
  request(m: AnyMessage, what: string): () => Promise<AnyMessage> {
    this.#connection.send(m);
    const id = toHex(m.messageId);
    return () =>
      this.#until(() => {
        const i = this.#inbox.findIndex(
          (r) => r.correlationId !== undefined && toHex(r.correlationId) === id,
        );
        return i === -1 ? undefined : this.#inbox.splice(i, 1)[0];
      }, what);
  }

  close(): void {
    this.#connection.close("the invitation claim finished");
  }
}

const NEVER = new Promise<never>(() => undefined);

async function openAsInvitee(
  s: ClaimSession,
  R: ResourceId,
  grantId: ControlRecordId,
): Promise<readonly ControlHeadRef[]> {
  const reply = await s.request(
    createMessage("RESOURCE_OPEN", {
      resourceId: R,
      heads: [],
      haves: [],
      grantIds: [hash32(grantId)],
    }),
    "RESOURCE_OPENED",
  )();
  if (reply.type === "NACK")
    throw new Unavailable(`RESOURCE_OPEN was refused: ${codeName(reply.body.code)}`);
  if (reply.type !== "RESOURCE_OPENED")
    throw new Unavailable(`RESOURCE_OPEN was answered with ${reply.type}`);
  return reply.body.heads;
}

/**
 * Control Records from `have.length` on, until the chain validates and
 * reaches `until`: a sequence, or the head a CONTROL_HEAD_MISMATCH named.
 */
async function fetchChain(
  s: ClaimSession,
  R: ResourceId,
  have: readonly Uint8Array[],
  until: { readonly seq: bigint } | { readonly head: Uint8Array },
): Promise<Linear> {
  const next = s.request(
    createMessage("CONTROL_GET", {
      resourceId: R,
      start: BigInt(have.length),
      end: "seq" in until ? until.seq : UINT64_MAX,
    }),
    "CONTROL_BATCH",
  );
  const records = [...have];
  for (;;) {
    const reply = await next();
    if (reply.type === "NACK")
      throw new Unavailable(`CONTROL_GET was refused: ${codeName(reply.body.code)}`);
    if (reply.type !== "CONTROL_BATCH") continue;
    for (const bytes of (reply as LfcpMessage<"CONTROL_BATCH">).body.objects)
      if (parseControlRecord(bytes).payload.controlSeq === BigInt(records.length))
        records.push(bytes);
    const chain = validateControlChain(records);
    if (chain.kind === "conflict")
      throw new Unavailable("the Control Chain is forked: no claim is made (§42)");
    if (chain.kind !== "linear") continue;
    if ("seq" in until ? chain.state.seq >= until.seq : bytesEqual(chain.state.head, until.head))
      return chain;
  }
}

/**
 * The joiner's side (§18.1, §18.2, §73). On "claimed" the claimant's
 * storage holds the chain with the claimant's grant and its secrets the
 * DEK: open the Resource with a SyncClient for the claimant. With
 * `dataProfiles`, a Resource of another Data Profile is
 * "profile-unsupported" before the Key Package and the claim. Throws
 * INVALID_INVITATION for a link without a secret or a secret that is not
 * the grant's subject, MISSING_DEPENDENCY when the grant is not on the
 * chain, and KEY_PACKAGE_OPEN_FAILED when no package delivers the current
 * epoch's DEK; transport and server stops are "unavailable".
 */
export async function acceptInvitation(
  options: AcceptInvitationOptions,
): Promise<AcceptedInvitation> {
  const invitation = parseInviteUri(
    typeof options.link === "string" ? options.link : options.link.reveal(),
  );
  const secret =
    invitation.secret ??
    fail("INVALID_INVITATION", "the link has no #secret= fragment: it is a targeted invitation");
  const R = invitation.resourceId;
  const invitee: Signer = Object.freeze({
    key: secret.signingKey,
    descriptor: invitationPrincipal(secret),
  });
  const s = new ClaimSession(
    {
      url: options.url ?? (invitation.endpoints[0] as string),
      signer: invitee,
      now: options.now,
      ...(options.webSocket === undefined ? {} : { webSocket: options.webSocket }),
    },
    options.timeout ?? NEVER,
  );
  const progress = (stage: AcceptInvitationStage, attempt?: number): void =>
    options.onProgress?.(Object.freeze(attempt === undefined ? { stage } : { stage, attempt }));
  try {
    // §73: the Invitation Principal authenticates and opens the Resource.
    progress("connecting");
    await s.connect();
    progress("validating-invitation");
    const heads = await openAsInvitee(s, R, invitation.grantId);
    if (heads.length !== 1)
      throw new Unavailable("the Resource has no single Control Head: no claim is made (§42)");
    let chain = await fetchChain(s, R, [], { seq: (heads[0] as ControlHeadRef).seq });

    // §18.2: the secret's Principal must be the grant's subject before the secret is used further.
    const claimSigner = verifyInvitationSecret(chain.state, invitation.grantId, secret);
    const grant =
      chain.state.grants.get(toHex(invitation.grantId)) ??
      fail("MISSING_DEPENDENCY", "the invitation grant is not on the chain");

    // §27: a profile the caller cannot open is refused before the DEK and the claim.
    if (
      options.dataProfiles !== undefined &&
      !options.dataProfiles.includes(chain.state.dataProfile)
    )
      return Object.freeze({
        kind: "profile-unsupported",
        resourceId: R,
        code: "PROFILE_UNSUPPORTED",
        dataProfile: chain.state.dataProfile,
      });

    // §73, §25.2: the invitation's Key Package delivers the DEK.
    progress("retrieving-key");
    const batch = await s.request(
      createMessage("KEY_PACKAGE_GET", {
        resourceId: R,
        recipient: invitee.descriptor.principalId,
        // §52: at most 256 epochs. The claim needs the current epoch's DEK,
        // and the invitation's package is of a recent epoch: the newest 256.
        epochs: [...chain.state.epochs.values()].map((e) => e.epoch).slice(-256),
      }),
      "KEY_PACKAGE_BATCH",
    )();
    if (batch.type !== "KEY_PACKAGE_BATCH")
      throw new Unavailable(
        batch.type === "NACK"
          ? `KEY_PACKAGE_GET was refused: ${codeName(batch.body.code)}`
          : `KEY_PACKAGE_GET was answered with ${batch.type}`,
      );
    const deks = new Map<string, ResourceDEK>();
    let problem = "no Key Package for the Invitation Principal";
    for (const bytes of batch.body.objects) {
      const r = await receiveKeyPackage(chain, bytes, {
        descriptor: invitee.descriptor,
        agreement: secret.agreementKey,
      });
      if (r.kind === "opened") deks.set(String(r.epoch), r.dek);
      else problem = r.kind === "rejected" ? r.wireCode : r.code;
    }
    if (!deks.has(String(chain.state.epoch.epoch)))
      fail("KEY_PACKAGE_OPEN_FAILED", `the current epoch's DEK was not delivered (${problem})`);

    // §18.1: the claim, signed by the Invitation Principal, at the current head (§47).
    const delegable = grant.delegable.includes(ABILITY.INVITE_CLAIM);
    const abilities =
      options.abilities ?? grant.abilities.filter((a) => a !== ABILITY.INVITE_CLAIM || delegable);
    const attempts: string[] = [];
    for (;;) {
      progress("claiming-capability", attempts.length + 1);
      const claim = signControlRecord(
        { resourceId: R, controlSeq: chain.state.seq + 1n, prevControlId: chain.state.head },
        {
          type: "CAPABILITY_CLAIM",
          invitationGrantId: invitation.grantId,
          claimant: options.claimant.signer.descriptor,
          abilities,
        },
        claimSigner,
      );
      const answer = await s.request(
        createMessage("CONTROL_PUT", {
          resourceId: R,
          expectedHead: chain.state.head,
          record: claim.bytes,
        }),
        "the CONTROL_PUT answer",
      )();
      if (answer.type === "ACK") {
        attempts.push("ACK");
        const claimed = validateControlChain([
          ...chain.records.map((r) => r.signed.bytes),
          claim.bytes,
        ]);
        if (claimed.kind !== "linear")
          fail("INVALID_CONTROL_CHAIN", "the acknowledged claim does not validate locally");
        await persist(options, claimed as Linear, deks);
        return Object.freeze({
          kind: "claimed",
          resourceId: R,
          grantId: claim.recordId,
          abilities: Object.freeze([...abilities]),
          epochs: Object.freeze([...deks.keys()].map((e) => BigInt(e) as DataEpoch)),
          attempts: Object.freeze(attempts),
        });
      }
      if (answer.type !== "NACK")
        throw new Unavailable(`CONTROL_PUT was answered with ${answer.type}`);
      const code = codeName(answer.body.code);
      attempts.push(code);
      const head = answer.body.details;
      // One refresh after a lost race (§73); the coordinator's next answer is final.
      if (code !== "CONTROL_HEAD_MISMATCH" || attempts.length > 1 || !(head instanceof Uint8Array))
        return Object.freeze({
          kind: "refused",
          resourceId: R,
          code,
          attempts: Object.freeze(attempts),
        });
      chain = await fetchChain(
        s,
        R,
        chain.records.map((r) => r.signed.bytes),
        { head },
      );
    }
  } catch (e) {
    if (e instanceof Unavailable)
      return Object.freeze({ kind: "unavailable", resourceId: R, reason: e.message });
    throw e;
  } finally {
    s.close();
  }
}

/** The claimant's storage: the chain with its grant, then each DEK before the row that names it (LFCP-034). */
async function persist(
  options: AcceptInvitationOptions,
  chain: Linear,
  deks: ReadonlyMap<string, ResourceDEK>,
): Promise<void> {
  const R = chain.state.resourceId;
  const before = await loadControlChain(options.storage, R);
  const saved = await saveControlChain(
    options.storage,
    chain,
    before?.kind === "linear" ? before.state.head : null,
  );
  if (!saved.ok) fail("UNSUPPORTED_VALUE", `the claimed chain was not stored: ${saved.reason}`);
  for (const row of await options.storage.control.epochs(R)) {
    const dek = deks.get(String(row.epoch));
    if (dek === undefined) continue;
    const ref = dekSecretRef(R, row.epoch);
    await options.secrets.put(ref, exportSecretKeyBytes(dek));
    const result = await options.storage.commit([
      { op: "put-epoch", resourceId: R, epoch: { ...row, dekRef: ref } },
    ]);
    if (!result.ok) fail("UNSUPPORTED_VALUE", `the DEK reference was not stored: ${result.reason}`);
  }
}
