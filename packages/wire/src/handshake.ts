import { bytesEqual, LfcpError, type PrincipalId, principalId, secureRandom } from "@openlfcp/core";
import { decodeDeterministic, encode } from "./cbor/index.js";
import { parseSignedObject, type Signer, signObject, verifySignedObject } from "./cose.js";
import {
  type AnyMessage,
  type CoreMessageType,
  createMessage,
  ERROR_CODE,
  type LfcpMessage,
  replyTo,
  type WireErrorName,
} from "./message.js";
import {
  type PrincipalDescriptor,
  principalDescriptorFromCbor,
  principalDescriptorToCbor,
} from "./principal.js";

/**
 * The LFCP session handshake (LFCP-WIRE-01 §34-§37): HELLO → CHALLENGE →
 * AUTH → READY, as pure functions over decoded messages. No sockets.
 *
 * The handshake authenticates the session Principal: it proves possession
 * of the Ed25519 key of the descriptor sent in HELLO, bound to this
 * session's nonces, session ID and server ID. It grants no Resource
 * authority: AuthenticatedSession has no abilities, and the optional
 * hosting credential is an opaque server-policy value, never a capability
 * (§36). Resource authority comes only from Control Chains (capability.ts).
 */

/** The wire profile this SDK implements (§34). */
export const WIRE_PROFILE = "LFCP-WIRE-01";

const AUTH_LABEL = "LFCP-AUTH-v1";
const NONCE = 16;
const SERVER_ID = 32;

/**
 * A source of random bytes. Production code leaves it out (the platform
 * CSPRNG, core secureRandom). Passing one is FOR TESTS ONLY: reproducible
 * nonces and session IDs defeat the handshake's freshness.
 */
export type RandomSource = (length: number) => Uint8Array;

/** The values the §36 transcript binds. */
export interface AuthTranscriptFields {
  readonly sessionId: Uint8Array;
  readonly clientNonce: Uint8Array;
  readonly serverNonce: Uint8Array;
  readonly serverId: Uint8Array;
  readonly principalId: PrincipalId;
}

function sized(what: string, v: unknown, length: number): Uint8Array {
  if (!(v instanceof Uint8Array) || v.length !== length)
    throw new LfcpError("INVALID_STRUCTURE", `${what} must be ${length} bytes`);
  return v;
}

/**
 * §36: deterministic CBOR of ["LFCP-AUTH-v1", session_id, client_nonce,
 * server_nonce, server_id, principal_id]; nothing else.
 */
export function authTranscript(f: AuthTranscriptFields): Uint8Array {
  return encode([
    AUTH_LABEL,
    sized("the session id", f.sessionId, NONCE),
    sized("the client nonce", f.clientNonce, NONCE),
    sized("the server nonce", f.serverNonce, NONCE),
    sized("the server id", f.serverId, SERVER_ID),
    sized("the Principal ID", f.principalId, 32),
  ]);
}

/** Decodes an auth transcript strictly: deterministic CBOR, the label, six elements, exact sizes. */
export function decodeAuthTranscript(bytes: Uint8Array): AuthTranscriptFields {
  const v = decodeDeterministic(bytes);
  if (!Array.isArray(v) || v.length !== 6 || v[0] !== AUTH_LABEL)
    throw new LfcpError("INVALID_STRUCTURE", 'an auth transcript is ["LFCP-AUTH-v1", ...5 fields]');
  const [, sessionId, clientNonce, serverNonce, serverId, principal] = v;
  return Object.freeze({
    sessionId: Uint8Array.from(sized("the session id", sessionId, NONCE)),
    clientNonce: Uint8Array.from(sized("the client nonce", clientNonce, NONCE)),
    serverNonce: Uint8Array.from(sized("the server nonce", serverNonce, NONCE)),
    serverId: Uint8Array.from(sized("the server id", serverId, SERVER_ID)),
    principalId: principalId(sized("the Principal ID", principal, 32)),
  });
}

/** The AUTH proof: a §10 COSE_Sign1 by the session Principal over the exact transcript. */
export function signAuthProof(fields: AuthTranscriptFields, signer: Signer): Uint8Array {
  if (!bytesEqual(fields.principalId, signer.descriptor.principalId))
    throw new LfcpError("COSE_SIGNER_MISMATCH", "the transcript names another Principal");
  return signObject(authTranscript(fields), signer).bytes;
}

export type AuthProofCheck =
  | { readonly valid: true }
  | {
      readonly valid: false;
      readonly reason: "MALFORMED" | "TRANSCRIPT_MISMATCH" | "KID_MISMATCH" | "BAD_SIGNATURE";
    };

/**
 * §36: the proof must be a §10 signed object whose kid is the HELLO
 * Principal, whose payload is exactly this session's transcript, and whose
 * signature verifies (§10.5.1). Every failure is AUTH_FAILED (G-MSG4).
 */
export function verifyAuthProof(
  proof: Uint8Array,
  expected: AuthTranscriptFields,
  principal: PrincipalDescriptor,
): AuthProofCheck {
  let signed: ReturnType<typeof parseSignedObject>;
  try {
    signed = parseSignedObject(proof);
  } catch {
    return { valid: false, reason: "MALFORMED" };
  }
  if (!bytesEqual(signed.payloadBytes, authTranscript(expected)))
    return { valid: false, reason: "TRANSCRIPT_MISMATCH" };
  const v = verifySignedObject(signed, principal);
  return v.valid ? { valid: true } : { valid: false, reason: v.reason };
}

/** The result of a successful handshake: who the session is, never what it may do. */
export interface AuthenticatedSession {
  readonly principal: PrincipalDescriptor;
  readonly wireProfile: string;
  readonly sessionId: Uint8Array;
  readonly serverId: Uint8Array;
  readonly dataProfiles?: readonly string[];
  /** The opaque hosting/account credential from AUTH: server policy only, not Resource authority. */
  readonly credential?: Uint8Array;
}

/**
 * §34 profile negotiation: the first profile the client offers that the
 * server supports, or undefined.
 */
export const selectWireProfile = (
  offered: readonly string[],
  supported: readonly string[],
): string | undefined => offered.find((p) => supported.includes(p));

/** Message types a server rejects before READY with AUTHORIZATION_FAILED (§64, G-MSG7). */
const RESOURCE_FAMILY: ReadonlySet<CoreMessageType> = new Set([
  "RESOURCE_HOST",
  "RESOURCE_HOSTED",
  "RESOURCE_OPEN",
  "RESOURCE_OPENED",
  "RESOURCE_CLOSE",
  "CONTROL_HAVE",
  "CONTROL_GET",
  "CONTROL_BATCH",
  "CONTROL_PUT",
  "DATA_HAVE",
  "DATA_GET",
  "DATA_BATCH",
  "DATA_PUT",
  "KEY_PACKAGE_GET",
  "KEY_PACKAGE_BATCH",
  "KEY_PACKAGE_PUT",
  "SNAPSHOT_GET",
  "SNAPSHOT",
  "SNAPSHOT_PUT",
  "PRESENCE",
  "PRESENCE_LEAVE",
]);

/** Whether a message type is a Resource, Control, Data, Key, Snapshot or Presence message. */
export const isResourceMessage = (type: AnyMessage["type"]): boolean =>
  type !== "EXTENSION" && RESOURCE_FAMILY.has(type);

const errorTo = (request: AnyMessage, code: WireErrorName, diagnostic: string) =>
  replyTo(request, "ERROR", { code: ERROR_CODE[code], diagnostic });
const nackTo = (request: AnyMessage, code: WireErrorName, diagnostic: string) =>
  replyTo(request, "NACK", { code: ERROR_CODE[code], diagnostic });

// ---------------------------------------------------------------------------
// Server side (§64)

export interface ServerHandshakeConfig {
  /** The stable 32-byte server ID, from server state; never derived from host, TLS or session values. */
  readonly serverId: Uint8Array;
  readonly wireProfiles: readonly string[];
  readonly maxMessageBytes: bigint;
  /** §37 durability level 0-3; an ACK must never claim more. */
  readonly durability: bigint;
  readonly heartbeatMs: bigint;
  readonly extensions?: readonly string[];
  /** TESTS ONLY (see RandomSource). */
  readonly random?: RandomSource;
}

export type ServerSession =
  | { readonly phase: "WAIT_HELLO" }
  | {
      readonly phase: "WAIT_AUTH";
      readonly principal: PrincipalDescriptor;
      readonly clientNonce: Uint8Array;
      readonly dataProfiles?: readonly string[];
      readonly wireProfile: string;
      readonly serverNonce: Uint8Array;
      readonly sessionId: Uint8Array;
    }
  | { readonly phase: "READY"; readonly session: AuthenticatedSession }
  | { readonly phase: "CLOSED"; readonly reason: string };

/** What the server does after one received message. */
export interface ServerStep {
  readonly session: ServerSession;
  /** Messages to send, in order. */
  readonly send: readonly AnyMessage[];
  /** Close the connection after sending. */
  readonly close: boolean;
  /** A READY-state message for the server's Resource logic. */
  readonly deliver?: AnyMessage;
}

/** §64: ACCEPTED moves straight to WAIT_HELLO. */
export const startServerSession = (): ServerSession => Object.freeze({ phase: "WAIT_HELLO" });

/**
 * One received message on a server session (§34-§37, §64). Before READY:
 * PING is answered with PONG, PONG and ERROR are accepted (G-SM4); Resource,
 * Control, Data, Key, Snapshot and Presence messages get
 * NACK(AUTHORIZATION_FAILED) (G-MSG7); any other out-of-order message is a
 * protocol violation: ERROR(MALFORMED_MESSAGE) and close. An invalid HELLO
 * descriptor or any AUTH proof failure is ERROR(AUTH_FAILED) and close
 * (P3, G-MSG4); no common profile is ERROR(PROTOCOL_UNSUPPORTED) and close.
 */
export function serverReceive(
  session: ServerSession,
  message: AnyMessage,
  config: ServerHandshakeConfig,
): ServerStep {
  const step = (s: ServerSession, send: AnyMessage[] = [], close = false): ServerStep =>
    Object.freeze({ session: s, send: Object.freeze(send), close });
  const fatal = (code: WireErrorName, why: string): ServerStep =>
    step(
      Object.freeze({ phase: "CLOSED", reason: `${code}: ${why}` }),
      [errorTo(message, code, why)],
      true,
    );
  if (session.phase === "CLOSED") return step(session, [], true);
  if (message.type === "PING") return step(session, [replyTo(message, "PONG", message.body)]);
  if (message.type === "PONG" || message.type === "ERROR")
    return session.phase === "READY"
      ? Object.freeze({ ...step(session), deliver: message })
      : step(session);
  if (session.phase !== "READY" && isResourceMessage(message.type))
    return step(session, [
      nackTo(message, "AUTHORIZATION_FAILED", "the session is not READY (§64)"),
    ]);

  switch (session.phase) {
    case "WAIT_HELLO": {
      if (message.type !== "HELLO")
        return fatal("MALFORMED_MESSAGE", `${message.type} before HELLO`);
      const body = message.body;
      let principal: PrincipalDescriptor;
      try {
        // §7: recompute the ID and validate the Ed25519 key (G-RS2) at receipt.
        principal = principalDescriptorFromCbor(principalDescriptorToCbor(body.principal));
      } catch {
        return fatal("AUTH_FAILED", "the HELLO Principal Descriptor is invalid (§7)");
      }
      const wireProfile = selectWireProfile(body.wireProfiles, config.wireProfiles);
      if (wireProfile === undefined)
        return fatal("PROTOCOL_UNSUPPORTED", "no offered wire profile is supported (§34)");
      const random = config.random ?? secureRandom;
      const serverNonce = sized("the server nonce", random(NONCE), NONCE);
      const sessionId = sized("the session id", random(NONCE), NONCE);
      const serverId = sized("the server id", config.serverId, SERVER_ID);
      return step(
        Object.freeze({
          phase: "WAIT_AUTH",
          principal,
          clientNonce: body.clientNonce,
          ...(body.dataProfiles !== undefined ? { dataProfiles: body.dataProfiles } : {}),
          wireProfile,
          serverNonce,
          sessionId,
        }),
        [replyTo(message, "CHALLENGE", { wireProfile, serverNonce, sessionId, serverId })],
      );
    }
    case "WAIT_AUTH": {
      if (message.type !== "AUTH") return fatal("MALFORMED_MESSAGE", `${message.type} before AUTH`);
      const proof = verifyAuthProof(
        message.body.proof,
        {
          sessionId: session.sessionId,
          clientNonce: session.clientNonce,
          serverNonce: session.serverNonce,
          serverId: config.serverId,
          principalId: session.principal.principalId,
        },
        session.principal,
      );
      if (!proof.valid) return fatal("AUTH_FAILED", `the AUTH proof fails (${proof.reason}, §36)`);
      const authenticated: AuthenticatedSession = Object.freeze({
        principal: session.principal,
        wireProfile: session.wireProfile,
        sessionId: session.sessionId,
        serverId: Uint8Array.from(config.serverId),
        ...(session.dataProfiles !== undefined ? { dataProfiles: session.dataProfiles } : {}),
        ...(message.body.credential !== undefined ? { credential: message.body.credential } : {}),
      });
      return step(Object.freeze({ phase: "READY", session: authenticated }), [
        replyTo(message, "READY", {
          wireProfile: session.wireProfile,
          serverId: Uint8Array.from(config.serverId),
          maxMessageBytes: config.maxMessageBytes,
          durability: config.durability,
          heartbeatMs: config.heartbeatMs,
          ...(config.extensions !== undefined ? { extensions: config.extensions } : {}),
        }),
      ]);
    }
    case "READY":
      if (
        message.type === "HELLO" ||
        message.type === "AUTH" ||
        message.type === "CHALLENGE" ||
        message.type === "READY"
      )
        return fatal("MALFORMED_MESSAGE", `${message.type} on an authenticated session`);
      return Object.freeze({ ...step(session), deliver: message });
  }
}

// ---------------------------------------------------------------------------
// Client side (§63)

export interface ClientHandshakeConfig {
  readonly signer: Signer;
  readonly wireProfiles?: readonly string[];
  readonly dataProfiles?: readonly string[];
  /** An opaque hosting/account credential for AUTH (§36); server policy only. */
  readonly credential?: Uint8Array;
  /** The server ID the client expects, when it knows it (e.g. from a Route Manifest). */
  readonly expectedServerId?: Uint8Array;
  /** TESTS ONLY (see RandomSource). */
  readonly random?: RandomSource;
}

/** The parameters READY grants the session (§37). */
export interface ReadySession {
  readonly wireProfile: string;
  readonly serverId: Uint8Array;
  readonly sessionId: Uint8Array;
  readonly maxMessageBytes: bigint;
  readonly durability: bigint;
  readonly heartbeatMs: bigint;
  readonly extensions: readonly string[];
}

export type ClientSession =
  | {
      readonly phase: "NEGOTIATING";
      readonly hello: LfcpMessage<"HELLO">;
    }
  | {
      readonly phase: "AUTHENTICATING";
      readonly hello: LfcpMessage<"HELLO">;
      readonly wireProfile: string;
      readonly serverId: Uint8Array;
      readonly sessionId: Uint8Array;
    }
  | { readonly phase: "READY"; readonly ready: ReadySession }
  | { readonly phase: "DISCONNECTED"; readonly reason: string };

export interface ClientStep {
  readonly session: ClientSession;
  readonly send: readonly AnyMessage[];
  readonly close: boolean;
  readonly deliver?: AnyMessage;
}

/** Starts the handshake once the WebSocket with lfcp-1 is open: the HELLO to send (§34). */
export function startClientHandshake(config: ClientHandshakeConfig): ClientStep {
  const random = config.random ?? secureRandom;
  const hello = createMessage("HELLO", {
    wireProfiles: config.wireProfiles ?? [WIRE_PROFILE],
    principal: config.signer.descriptor,
    clientNonce: sized("the client nonce", random(NONCE), NONCE),
    ...(config.dataProfiles !== undefined ? { dataProfiles: config.dataProfiles } : {}),
  });
  return Object.freeze({
    session: Object.freeze({ phase: "NEGOTIATING", hello }),
    send: Object.freeze([hello]),
    close: false,
  });
}

/**
 * One received message on a client session. CHALLENGE must select a
 * profile the client offered (else PROTOCOL_UNSUPPORTED) and, when the
 * client expects one, name its server ID; the client then signs the
 * transcript. READY must repeat the selected profile and the CHALLENGE's
 * server ID (else MALFORMED_MESSAGE). An ERROR before READY ends the
 * handshake. Failures close the connection.
 */
export function clientReceive(
  session: ClientSession,
  message: AnyMessage,
  config: ClientHandshakeConfig,
): ClientStep {
  const step = (s: ClientSession, send: AnyMessage[] = [], close = false): ClientStep =>
    Object.freeze({ session: s, send: Object.freeze(send), close });
  const fail = (code: WireErrorName, why: string, notify = true): ClientStep =>
    step(
      Object.freeze({ phase: "DISCONNECTED", reason: `${code}: ${why}` }),
      notify ? [errorTo(message, code, why)] : [],
      true,
    );
  if (session.phase === "DISCONNECTED") return step(session, [], true);
  if (message.type === "PING") return step(session, [replyTo(message, "PONG", message.body)]);
  if (message.type === "PONG") return step(session);
  if (message.type === "ERROR" && session.phase !== "READY")
    return fail("MALFORMED_MESSAGE", `the server sent ERROR ${message.body.code}`, false);

  switch (session.phase) {
    case "NEGOTIATING": {
      if (message.type !== "CHALLENGE")
        return fail("MALFORMED_MESSAGE", `${message.type} before CHALLENGE`);
      const c = message.body;
      if (!session.hello.body.wireProfiles.includes(c.wireProfile))
        return fail(
          "PROTOCOL_UNSUPPORTED",
          `the server selected ${c.wireProfile}, which was not offered`,
        );
      if (config.expectedServerId !== undefined && !bytesEqual(c.serverId, config.expectedServerId))
        return fail("AUTH_FAILED", "the CHALLENGE names another server");
      const proof = signAuthProof(
        {
          sessionId: c.sessionId,
          clientNonce: session.hello.body.clientNonce,
          serverNonce: c.serverNonce,
          serverId: c.serverId,
          principalId: config.signer.descriptor.principalId,
        },
        config.signer,
      );
      const auth = replyTo(message, "AUTH", {
        proof,
        ...(config.credential !== undefined ? { credential: config.credential } : {}),
      });
      return step(
        Object.freeze({
          phase: "AUTHENTICATING",
          hello: session.hello,
          wireProfile: c.wireProfile,
          serverId: c.serverId,
          sessionId: c.sessionId,
        }),
        [auth],
      );
    }
    case "AUTHENTICATING": {
      if (message.type !== "READY")
        return fail("MALFORMED_MESSAGE", `${message.type} before READY`);
      const r = message.body;
      if (r.wireProfile !== session.wireProfile)
        return fail("MALFORMED_MESSAGE", "READY names another wire profile than CHALLENGE");
      if (!bytesEqual(r.serverId, session.serverId))
        return fail("MALFORMED_MESSAGE", "READY names another server than CHALLENGE");
      return step(
        Object.freeze({
          phase: "READY",
          ready: Object.freeze({
            wireProfile: r.wireProfile,
            serverId: r.serverId,
            sessionId: session.sessionId,
            maxMessageBytes: r.maxMessageBytes,
            durability: r.durability,
            heartbeatMs: r.heartbeatMs,
            extensions: r.extensions ?? [],
          }),
        }),
      );
    }
    case "READY":
      if (message.type === "CHALLENGE" || message.type === "READY")
        return fail("MALFORMED_MESSAGE", `${message.type} on an authenticated session`);
      return Object.freeze({ ...step(session), deliver: message });
  }
}
