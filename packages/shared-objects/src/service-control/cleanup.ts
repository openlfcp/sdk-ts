import type { ServiceControlValidation } from "./schema.js";
import { FINAL_EVENT_STATES } from "./values.js";
import type { ServiceControlIntent } from "./write.js";

/** §9: entries are deleted for display 7 days after they became final. */
export const SERVICE_CONTROL_DISPLAY_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface ServiceControlCleanupOptions {
  /** Days after becoming final; default SERVICE_CONTROL_DISPLAY_DAYS. */
  readonly days?: number;
  /**
   * When the service marked a question `superseded` (RFC 3339), from its own
   * records: the entry holds no time for it. Without it a superseded
   * question and its answers are kept.
   */
  readonly supersededAt?: (qid: string) => string | undefined;
}

/**
 * SERVICE-CONTROL-PROFILE-01 §9 "Deletion for display", for the service:
 * the changes that delete what has been final for at least `days` days, each
 * admissible by the mutation table of §3 on `state` (the state readers see,
 * §5), each counted from the time the entry became final, never from its
 * creation. One change per request: the request with its event, its cancel
 * and its pairing entry when §3 lets that go too (the approval is present,
 * or the request was cancelled or rejected), from its final event's time;
 * one per settled question, once it and every answer to it are old enough:
 * the question, its answers and their final events (an answer whose event
 * is not final, or that has none yet, holds its question); answers and pairing
 * entries left behind once §3 allows it. Deletion removes nothing
 * from history (SOP §56) and is never a deduplication boundary (§10): the
 * service keeps its execution records.
 */
export function serviceControlCleanup(
  state: ServiceControlValidation,
  now: number,
  options: ServiceControlCleanupOptions = {},
): ServiceControlIntent[][] {
  const days = options.days ?? SERVICE_CONTROL_DISPLAY_DAYS;
  const due = (at: string | undefined) => at !== undefined && Date.parse(at) <= now - days * DAY_MS;
  const latest = (...at: (string | undefined)[]) =>
    at.includes(undefined)
      ? undefined
      : (at as string[]).reduce((a, b) => (Date.parse(a) >= Date.parse(b) ? a : b));
  const del = (
    container: Extract<ServiceControlIntent, { intent: "delete" }>["container"],
    key: string,
  ): ServiceControlIntent => ({ intent: "delete", container, key });
  const final = (id: string) => {
    const e = state.events[id];
    return e !== undefined && FINAL_EVENT_STATES.has(e.state) ? e : undefined;
  };
  const changes: ServiceControlIntent[][] = [];
  for (const rid of Object.keys(state.requests)) {
    const event = final(rid);
    if (event === undefined || !due(event.at)) continue;
    const change = [del("requests", rid), del("events", rid)];
    if (state.cancels[rid] !== undefined) change.push(del("cancels", rid));
    const pairing = state.pairing[rid];
    if (
      pairing !== undefined &&
      (state.approvals[pairing.principal] !== undefined ||
        event.state === "cancelled" ||
        event.state === "rejected")
    )
      change.push(del("pairing", rid));
    changes.push(change);
  }
  const answersOf = new Map<string, string[]>();
  for (const [aid, a] of Object.entries(state.answers))
    answersOf.set(a.qid, [...(answersOf.get(a.qid) ?? []), aid]);
  // An answer is settled when its event is final, at that event's time (§9:
  // from when it became final). Without a final event it is not settled,
  // whether its event still runs or the service has not written one yet: the
  // answer's own time is when it was created, never when it became final.
  const answerSettledAt = (aid: string) => {
    const a = state.answers[aid];
    if (a === undefined) return undefined;
    return latest(a.at, final(aid)?.at);
  };
  const answerChange = (aid: string) => [del("answers", aid), del("events", aid)];
  for (const [qid, q] of Object.entries(state.questions)) {
    // `superseded` carries no time (§2.1): only the service's own record says when.
    const settledAt =
      q.resolved !== undefined
        ? q.resolved.at
        : q.superseded !== undefined
          ? options.supersededAt?.(qid)
          : undefined;
    const aids = answersOf.get(qid) ?? [];
    if (!due(settledAt) || !aids.every((aid) => due(answerSettledAt(aid)))) continue;
    changes.push([...aids.flatMap(answerChange), del("questions", qid)]);
  }
  // Left behind: answers to a question already deleted, pairing entries whose
  // approval came after their request was deleted (§3).
  for (const [qid, aids] of answersOf)
    if (state.questions[qid] === undefined)
      for (const aid of aids.filter((a) => due(answerSettledAt(a))))
        changes.push(answerChange(aid));
  for (const [rid, p] of Object.entries(state.pairing))
    if (state.requests[rid] === undefined && state.approvals[p.principal] !== undefined)
      changes.push([del("pairing", rid)]);
  return changes;
}
