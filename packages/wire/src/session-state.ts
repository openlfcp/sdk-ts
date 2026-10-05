/**
 * The LFCP connection state machines (LFCP-WIRE-01 §63, §64) as pure
 * transition functions: exactly the drawn edges, plus a connection-loss
 * edge from every live state (G-SM1) and the CONNECTING failure edge
 * (G-SM3). An event that has no edge from the current state returns
 * undefined: the caller treats it as a protocol violation. No I/O.
 *
 * The per-resource sync machine (§65) belongs to the client sync session
 * (LFCP-039a).
 */

/** §63 client connection states. */
export type ClientConnectionState =
  | "DISCONNECTED"
  | "CONNECTING"
  | "NEGOTIATING"
  | "AUTHENTICATING"
  | "READY";

export type ClientConnectionEvent =
  /** open WebSocket */
  | "OPEN"
  /** WebSocket + lfcp-1 accepted */
  | "CONNECTED"
  /** connection failed or lfcp-1 not accepted (G-SM3) */
  | "CONNECT_FAILED"
  /** HELLO sent, CHALLENGE received */
  | "CHALLENGED"
  /** AUTH sent, READY received */
  | "READY_RECEIVED"
  /** open/close resources while READY */
  | "RESOURCE"
  /** a fatal error during negotiation */
  | "FATAL_ERROR"
  | "AUTH_FAILURE"
  /** the socket closed or the connection was lost (G-SM1) */
  | "CONNECTION_LOST";

const CLIENT: Readonly<
  Record<ClientConnectionState, Partial<Record<ClientConnectionEvent, ClientConnectionState>>>
> = {
  DISCONNECTED: { OPEN: "CONNECTING" },
  CONNECTING: {
    CONNECTED: "NEGOTIATING",
    CONNECT_FAILED: "DISCONNECTED",
    CONNECTION_LOST: "DISCONNECTED",
  },
  NEGOTIATING: {
    CHALLENGED: "AUTHENTICATING",
    FATAL_ERROR: "DISCONNECTED",
    CONNECTION_LOST: "DISCONNECTED",
  },
  AUTHENTICATING: {
    READY_RECEIVED: "READY",
    AUTH_FAILURE: "DISCONNECTED",
    CONNECTION_LOST: "DISCONNECTED",
  },
  READY: { RESOURCE: "READY", CONNECTION_LOST: "DISCONNECTED" },
};

/** The §63 client transition, or undefined when the event has no edge from `state`. */
export function clientConnectionTransition(
  state: ClientConnectionState,
  event: ClientConnectionEvent,
): ClientConnectionState | undefined {
  return CLIENT[state][event];
}

/** §64 server session states. */
export type ServerSessionState = "ACCEPTED" | "WAIT_HELLO" | "WAIT_AUTH" | "READY" | "CLOSED";

export type ServerSessionEvent =
  /** the session starts waiting for HELLO */
  | "START"
  /** valid HELLO, CHALLENGE sent */
  | "VALID_HELLO"
  /** valid AUTH, READY sent */
  | "VALID_AUTH"
  /** an LFCP message on a READY session */
  | "MESSAGE"
  | "PROTOCOL_VIOLATION"
  | "AUTH_FAILURE"
  | "FATAL_ERROR"
  /** the socket closed (G-SM1) */
  | "SOCKET_CLOSED";

const SERVER: Readonly<
  Record<ServerSessionState, Partial<Record<ServerSessionEvent, ServerSessionState>>>
> = {
  ACCEPTED: { START: "WAIT_HELLO", SOCKET_CLOSED: "CLOSED" },
  WAIT_HELLO: {
    VALID_HELLO: "WAIT_AUTH",
    PROTOCOL_VIOLATION: "CLOSED",
    SOCKET_CLOSED: "CLOSED",
  },
  WAIT_AUTH: { VALID_AUTH: "READY", AUTH_FAILURE: "CLOSED", SOCKET_CLOSED: "CLOSED" },
  READY: { MESSAGE: "READY", FATAL_ERROR: "CLOSED", SOCKET_CLOSED: "CLOSED" },
  CLOSED: {},
};

/** The §64 server transition, or undefined when the event has no edge from `state`. */
export function serverSessionTransition(
  state: ServerSessionState,
  event: ServerSessionEvent,
): ServerSessionState | undefined {
  return SERVER[state][event];
}
