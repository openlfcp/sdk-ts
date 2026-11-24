import type { ServiceControlIntent } from "./write.js";

/** A§3.5: a unit carrying `status.heartbeatAt` at least this often. */
export const HEARTBEAT_INTERVAL_MS = 30 * 60_000;
/** A§3.5: the status and each binding written at most once in this window. */
export const TRANSITION_INTERVAL_MS = 60_000;

type Fields = Record<string, unknown>;
/** `status`, or `bindings/<id>`. */
type Key = string;
const STATUS: Key = "status";
const bindingKey = (binding: string): Key => `bindings/${binding}`;

const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");

/**
 * A§3.5 (E-030): when the service writes `status` and `bindings` of C, so that C's history
 * stays in its budget. A transition (a field readers act on: state, pending, refused,
 * unconfirmed, needsAttention…) is written at once, but the status and each binding at most
 * once per {@link TRANSITION_INTERVAL_MS}: transitions inside that window are merged into
 * one write. Progress (`defer`: e.g. `lastCompleteCheckAt`, fresh for 75 min) never makes a
 * unit by itself; it rides the next one. `heartbeatAt` rides every unit, and makes a unit of
 * its own only when none was written for {@link HEARTBEAT_INTERVAL_MS}.
 *
 * Times are milliseconds since the epoch. The schedule only says what to write: callers ask
 * {@link due} (or wait until {@link nextAt}), and write the intents of {@link take} in one unit,
 * with any other intents of their own.
 */
export class ServiceControlStatusSchedule {
  readonly #written = new Map<Key, number>();
  readonly #transitions = new Map<Key, Fields>();
  readonly #progress = new Map<Key, Fields>();
  #heartbeat: number;

  /** `lastHeartbeat`: when a unit carrying `heartbeatAt` was last written (e.g. at start). */
  constructor(lastHeartbeat = Number.NEGATIVE_INFINITY) {
    this.#heartbeat = lastHeartbeat;
  }

  status(fields: Readonly<Fields>, options: { readonly defer?: boolean } = {}): void {
    this.#put(STATUS, fields, options.defer === true);
  }

  binding(
    binding: string,
    fields: Readonly<Fields>,
    options: { readonly defer?: boolean } = {},
  ): void {
    this.#put(bindingKey(binding), fields, options.defer === true);
  }

  #put(key: Key, fields: Readonly<Fields>, defer: boolean): void {
    const into = defer && !this.#transitions.has(key) ? this.#progress : this.#transitions;
    const merged = { ...this.#progress.get(key), ...into.get(key), ...fields };
    this.#progress.delete(key);
    into.set(key, merged);
  }

  #allowed(key: Key, now: number): boolean {
    return now - (this.#written.get(key) ?? Number.NEGATIVE_INFINITY) >= TRANSITION_INTERVAL_MS;
  }

  /** When a unit is next due: the earliest held transition, or else the heartbeat. */
  nextAt(): number {
    let at = this.#heartbeat + HEARTBEAT_INTERVAL_MS;
    for (const key of this.#transitions.keys())
      at = Math.min(
        at,
        (this.#written.get(key) ?? Number.NEGATIVE_INFINITY) + TRANSITION_INTERVAL_MS,
      );
    return at;
  }

  /** Whether a unit is due at `now`. */
  due(now: number): boolean {
    return now >= this.nextAt();
  }

  /**
   * The intents of a unit written at `now`: every held transition and progress whose window
   * allows it, and `heartbeatAt`. Callers write them (in a unit that may carry other intents)
   * whenever they write a unit, due or not; what they return counts as written.
   */
  take(now: number): ServiceControlIntent[] {
    const out = new Map<Key, Fields>();
    for (const held of [this.#progress, this.#transitions])
      for (const [key, fields] of held) {
        if (!this.#allowed(key, now)) continue;
        out.set(key, { ...out.get(key), ...fields });
        held.delete(key);
      }
    // The heartbeat is not a transition of the status: it does not hold the status back.
    const status = { ...out.get(STATUS), heartbeatAt: iso(now) };
    if (out.has(STATUS)) this.#written.set(STATUS, now);
    out.delete(STATUS);
    this.#heartbeat = now;
    const intents: ServiceControlIntent[] = [{ intent: "status.put", fields: status }];
    for (const [key, fields] of out) {
      this.#written.set(key, now);
      intents.push({ intent: "binding.put", binding: key.slice(bindingKey("").length), fields });
    }
    return intents;
  }
}
