import type { Receipt } from "./receipts.js";

/**
 * Typing coalescence (LFCP-02-025 acceptance 4): one Data Unit per typing
 * burst, not per key. A per-key change costs about 410 bytes of Data Unit
 * per character, a burst of 16 or more about 27 or less
 * (.github docs/devel/reports/section-scale-measurements.md §6).
 *
 * An adapter plans each pass against its projection's base, the
 * modelRevision of its last receipt (SDK-SECTIONS-INTEGRATION-01 §7.3,
 * §7.5): until a pass is committed, every later pass on the same base
 * contains its edits. So a pass that only edits Text may wait, and the
 * next pass on the same base replaces it; the waiting pass is never
 * committed alongside its replacement, which would apply its edits twice.
 * A pass is committed through `commit` (the durable §3 facade) when:
 *
 * - it holds any intent other than `text.edit` (a structural intent, a
 *   Task field): it carries the typing before it in the same change;
 * - it edits a node the waiting pass did not: the burst left a paragraph;
 * - a node it edits has another base than in the waiting pass: the base
 *   moved without a flush, so the waiting pass is committed first;
 * - its Text edits reach `maxChars` characters inserted or deleted, by
 *   default 256 (the §16.2 budget of 8,192 operations is the hard cap);
 * - no new pass came for `idleMs`, by default 1.5 s, when tick() runs
 *   (the adapter calls it from its own clock, like SyncClient.tick);
 * - flush() is called: before the adapter changes the projection's base
 *   any other way, before it closes, and whenever it must know the edit
 *   is durable.
 *
 * A waiting pass is not durable: it has no receipt and lives only in the
 * adapter's source, from which a pass after a crash plans it again. Its
 * operation ID was never committed, so receiptOf answers none for it.
 */

/** A `text.edit` intent, as far as coalescence reads it (SHARED-SECTIONS-PROFILE-01 §11). */
interface TextEditShape {
  readonly intent: "text.edit";
  readonly id: string;
  readonly base: string;
  readonly edits: readonly { readonly deleteCount: number; readonly insert: string }[];
}

const isTextEdit = (i: unknown): i is TextEditShape =>
  typeof i === "object" &&
  i !== null &&
  (i as { intent?: unknown }).intent === "text.edit" &&
  typeof (i as { id?: unknown }).id === "string" &&
  typeof (i as { base?: unknown }).base === "string" &&
  Array.isArray((i as { edits?: unknown }).edits);

/** What submit did with a pass. */
export type Submitted =
  /** Committed now: its receipt. */
  | { readonly kind: "committed"; readonly receipt: Receipt; readonly replaced: string | null }
  /** Waiting for more typing; `replaced` is the waiting pass it replaces, which is dropped. */
  | { readonly kind: "deferred"; readonly operationId: string; readonly replaced: string | null };

/** A waiting pass committed by tick() or flush(), or its failure. */
export type Flushed =
  | {
      readonly kind: "committed";
      readonly key: string;
      readonly operationId: string;
      readonly receipt: Receipt;
    }
  | {
      readonly kind: "failed";
      readonly key: string;
      readonly operationId: string;
      readonly intents: readonly unknown[];
      readonly error: unknown;
    };

export interface TypingCoalescerOptions {
  /** The durable commit (SyncClient.commit for the projection's Resource). */
  commit(intents: readonly unknown[], options: { readonly operationId: string }): Promise<Receipt>;
  /** A waiting pass was committed or failed outside submit (tick, flush). */
  onFlushed?(flushed: Flushed): void;
  /** Idle pause after which a waiting pass is committed (ms, default 1,500). */
  readonly idleMs?: number;
  /** Characters inserted or deleted after which a pass is committed (default 256). */
  readonly maxChars?: number;
  /** The local clock (ms), for the idle pause. */
  now(): number;
}

interface Waiting {
  readonly operationId: string;
  readonly intents: readonly unknown[];
  /** The base of each edited node. */
  readonly bases: ReadonlyMap<string, string>;
  /** When it was submitted. */
  readonly at: number;
}

export class TypingCoalescer {
  readonly #o: TypingCoalescerOptions;
  readonly #idleMs: number;
  readonly #maxChars: number;
  /** The waiting pass per key (a projection). */
  readonly #waiting = new Map<string, Waiting>();
  /** Serializes commits per key. */
  readonly #chain = new Map<string, Promise<unknown>>();

  constructor(options: TypingCoalescerOptions) {
    this.#o = options;
    this.#idleMs = options.idleMs ?? 1_500;
    this.#maxChars = options.maxChars ?? 256;
  }

  /**
   * Commits `intents` now or lets them wait for more typing (see above).
   * `key` names the projection whose base the pass was planned on.
   */
  submit(
    key: string,
    intents: readonly unknown[],
    options: { readonly operationId: string },
  ): Promise<Submitted> {
    return this.#serial(key, async () => {
      const waiting = this.#waiting.get(key);
      const textOnly = intents.length > 0 && intents.every(isTextEdit);
      const edits = intents.filter(isTextEdit);
      const bases = new Map(edits.map((e) => [e.id, e.base]));
      // A later pass on the same base contains the waiting one and replaces
      // it. A node edited on another base means the base moved without a
      // flush: the waiting pass is not contained, so it is committed first.
      let replaced: string | null = null;
      if (waiting !== undefined) {
        const sameBase = [...bases].every(
          ([id, base]) => !waiting.bases.has(id) || waiting.bases.get(id) === base,
        );
        this.#drop(key);
        if (sameBase) replaced = waiting.operationId;
        else await this.#commitWaiting(key, waiting, false);
      }
      const chars = edits.reduce(
        (n, e) => n + e.edits.reduce((m, x) => m + x.insert.length + x.deleteCount, 0),
        0,
      );
      // The burst moved to another paragraph: the pass ends it.
      const leftNode =
        waiting !== undefined &&
        replaced !== null &&
        [...bases.keys()].some((n) => !waiting.bases.has(n));
      if (!textOnly || chars >= this.#maxChars || leftNode) {
        const receipt = await this.#o.commit(intents, options);
        return { kind: "committed", receipt, replaced };
      }
      const w: Waiting = { operationId: options.operationId, intents, bases, at: this.#o.now() };
      this.#waiting.set(key, w);
      return { kind: "deferred", operationId: options.operationId, replaced };
    });
  }

  /** Commits every pass that waited `idleMs` or longer at `now`, reporting each through onFlushed. */
  async tick(now: number): Promise<void> {
    for (const [key, w] of [...this.#waiting])
      if (now - w.at >= this.#idleMs)
        await this.#serial(key, async () => {
          if (this.#waiting.get(key) !== w) return;
          this.#waiting.delete(key);
          await this.#commitWaiting(key, w, true);
        });
  }

  /** Commits the waiting pass of `key` (every key without one), reporting each through onFlushed. */
  async flush(key?: string): Promise<void> {
    const keys = key === undefined ? [...this.#waiting.keys()] : [key];
    for (const k of keys)
      await this.#serial(k, async () => {
        const w = this.#waiting.get(k);
        if (w === undefined) return;
        this.#drop(k);
        await this.#commitWaiting(k, w, true);
      });
  }

  /** The operation ID of the pass waiting for `key`, if any. */
  waiting(key: string): string | undefined {
    return this.#waiting.get(key)?.operationId;
  }

  #drop(key: string): void {
    this.#waiting.delete(key);
  }

  /** Commits a waiting pass; `report` sends the outcome to onFlushed, else a failure throws. */
  async #commitWaiting(key: string, w: Waiting, report: boolean): Promise<void> {
    try {
      const receipt = await this.#o.commit(w.intents, { operationId: w.operationId });
      this.#o.onFlushed?.({ kind: "committed", key, operationId: w.operationId, receipt });
    } catch (error) {
      this.#o.onFlushed?.({
        kind: "failed",
        key,
        operationId: w.operationId,
        intents: w.intents,
        error,
      });
      if (!report) throw error;
    }
  }

  #serial<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const run = (this.#chain.get(key) ?? Promise.resolve()).then(fn, fn);
    this.#chain.set(
      key,
      run.catch(() => undefined),
    );
    return run;
  }
}
