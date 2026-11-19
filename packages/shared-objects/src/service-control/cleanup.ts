import type { ServiceControlValidation } from "./schema.js";
import { FINAL_EVENT_STATES } from "./values.js";
import type { ServiceControlIntent } from "./write.js";

/** §9: entries are deleted for display 7 days after they became final. */
export const SERVICE_CONTROL_DISPLAY_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * SERVICE-CONTROL-PROFILE-01 §9 "Deletion for display", for the service:
 * the changes that delete what has been final for at least `days` days, each
 * admissible by the mutation table of §3 on `state` (the state readers see,
 * §5). One change per request: the request with its event, its cancel and
 * its pairing entry when §3 lets that go too (the approval is present, or
 * the request was cancelled or rejected); one per settled question: the
 * question, its answers and their final events; answers and pairing
 * entries left behind once §3 allows it. Deletion removes nothing
 * from history (SOP §56) and is never a deduplication boundary (§10): the
 * service keeps its execution records.
 */
export function serviceControlCleanup(
  state: ServiceControlValidation,
  now: number,
  days = SERVICE_CONTROL_DISPLAY_DAYS,
): ServiceControlIntent[][] {
  const due = (at: string | undefined) => at !== undefined && Date.parse(at) <= now - days * DAY_MS;
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
  for (const [qid, q] of Object.entries(state.questions)) {
    const settledAt = q.resolved?.at ?? (q.superseded === undefined ? undefined : q.at);
    if (!due(settledAt)) continue;
    const change: ServiceControlIntent[] = [];
    for (const aid of answersOf.get(qid) ?? []) {
      change.push(del("answers", aid));
      if (final(aid) !== undefined) change.push(del("events", aid));
    }
    change.push(del("questions", qid));
    changes.push(change);
  }
  // Left behind: answers to a question already deleted, pairing entries whose
  // approval came after their request was deleted (§3).
  for (const [qid, aids] of answersOf)
    if (state.questions[qid] === undefined)
      for (const aid of aids.filter((a) => due(state.answers[a]?.at)))
        changes.push(
          final(aid) === undefined
            ? [del("answers", aid)]
            : [del("answers", aid), del("events", aid)],
        );
  for (const [rid, p] of Object.entries(state.pairing))
    if (state.requests[rid] === undefined && state.approvals[p.principal] !== undefined)
      changes.push([del("pairing", rid)]);
  return changes;
}
