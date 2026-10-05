/**
 * The §65 per-Resource client sync state machine (LFCP-WIRE-01 §65) as a
 * pure transition function: exactly the drawn edges, plus the close edge
 * from every state but CLOSED (§65: "Every state moves to CLOSED on
 * RESOURCE_CLOSE or when the connection is lost"; CLOSED → CLOSED is
 * illegal). An event without an edge returns undefined.
 */

export type ResourcePhase =
  | "CLOSED"
  | "OPENING"
  | "CONTROL_SYNC"
  | "CONTROL_CONFLICT"
  | "KEY_SYNC"
  | "KEY_BLOCKED"
  | "DATA_SYNC"
  | "LIVE";

export type ResourcePhaseEvent =
  /** RESOURCE_OPEN sent */
  | "OPEN"
  /** RESOURCE_OPENED received */
  | "OPENED"
  /** multiple valid Control Heads */
  | "FORK"
  /** Control Chain complete */
  | "CONTROL_COMPLETE"
  /** the required DEK is available */
  | "DEK_AVAILABLE"
  /** a required Key Package is unavailable */
  | "KEY_UNAVAILABLE"
  /** a Key Package arrived (KEY_BLOCKED → KEY_SYNC) */
  | "PACKAGE_ARRIVED"
  /** snapshot/replay reached the known frontier */
  | "FRONTIER_REACHED"
  /** missing ranges detected while LIVE */
  | "MISSING_RANGES"
  /** a new Control Record received while LIVE */
  | "CONTROL_RECORD"
  /** RESOURCE_CLOSE, a manual close, or the connection was lost */
  | "CLOSE";

const EDGES: Readonly<Record<ResourcePhase, Partial<Record<ResourcePhaseEvent, ResourcePhase>>>> = {
  CLOSED: { OPEN: "OPENING" },
  OPENING: { OPENED: "CONTROL_SYNC" },
  CONTROL_SYNC: { FORK: "CONTROL_CONFLICT", CONTROL_COMPLETE: "KEY_SYNC" },
  CONTROL_CONFLICT: {},
  KEY_SYNC: { DEK_AVAILABLE: "DATA_SYNC", KEY_UNAVAILABLE: "KEY_BLOCKED" },
  KEY_BLOCKED: { PACKAGE_ARRIVED: "KEY_SYNC" },
  DATA_SYNC: { FRONTIER_REACHED: "LIVE" },
  LIVE: { MISSING_RANGES: "DATA_SYNC", CONTROL_RECORD: "CONTROL_SYNC" },
};

/** The §65 transition, or undefined when `event` has no edge from `state`. */
export function resourcePhaseTransition(
  state: ResourcePhase,
  event: ResourcePhaseEvent,
): ResourcePhase | undefined {
  if (event === "CLOSE") return state === "CLOSED" ? undefined : "CLOSED";
  return EDGES[state][event];
}
