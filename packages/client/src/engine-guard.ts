import { type ResourceId, toHex } from "@openlfcp/core";
import type { LfcpStorage } from "@openlfcp/storage";

/**
 * The crash-loop breaker: received content that traps the profile engine
 * (e.g. Automerge's wasm module, which then stays terminated for the whole
 * process) must not crash every restart again.
 *
 * Before an engine call on received content (applying Data Units, loading
 * a Snapshot), the items it covers are recorded durably
 * (`applying:<scope>:<resource>`, one record per scope: "units" for the
 * applier, "snapshots" for Snapshot loads); the record is removed when the call returns or
 * throws an ordinary error. A record found later means the process died
 * inside the call: a trap, or anything else (killed, power loss, a bug in
 * our own code).
 *
 * Blame needs two such crashes on the item alone:
 * - after a crash, every item of the leftover record becomes a suspect
 *   (`suspect:<resource>:<item>` = 1) and is applied alone from then on,
 *   never in a batch, so an innocent batch member is cleared by its own
 *   successful apply;
 * - a suspect that crashes again alone (count 2) is quarantined locally:
 *   never given to the engine again, here or on later delivery, and
 *   surfaced. The mark stays, so a re-delivered copy is refused too.
 *
 * So a single crash mid-apply (the normal crash-restart path) only costs a
 * retry; a unit is blamed only when it crashed the engine twice by itself.
 * A poison unit costs at most three process restarts (batch, alone, then
 * quarantined at the next start).
 */

/** A thrown value that looks like an engine trap (WebAssembly RuntimeError, a terminated module). */
export function isEngineTrap(e: unknown): boolean {
  const wasm = (globalThis as { WebAssembly?: { RuntimeError?: abstract new () => unknown } })
    .WebAssembly?.RuntimeError;
  if (wasm !== undefined && e instanceof wasm) return true;
  if (!(e instanceof Error)) return false;
  return (
    e.name === "RuntimeError" ||
    /\b(module|instance)\b.*\bterminated\b|\bunreachable\b executed|\bwasm trap\b/i.test(e.message)
  );
}

/** An item the engine processes: a Data Unit or a Snapshot, by ID. */
export type EngineItem = `unit:${string}` | `snapshot:${string}`;

export const unitItem = (id: Uint8Array): EngineItem => `unit:${toHex(id)}`;
export const snapshotItem = (id: Uint8Array): EngineItem => `snapshot:${toHex(id)}`;

/** How often an item crashed the engine: 1 suspect (applied alone), 2+ quarantined. */
export type Suspicion = 0 | 1 | 2;

export class EngineGuard {
  readonly #storage: Pick<LfcpStorage, "localMarks" | "commit">;
  readonly #scope: string;
  readonly #suspects = new Map<string, Map<string, number>>();
  readonly #recovering = new Map<string, Promise<EngineItem[]>>();

  constructor(storage: Pick<LfcpStorage, "localMarks" | "commit">, scope: "units" | "snapshots") {
    this.#storage = storage;
    this.#scope = scope;
  }

  #applying(R: string): string {
    return `applying:${this.#scope}:${R}`;
  }

  /**
   * Once per Resource and guard: turns a leftover `applying` record into
   * suspects (counting one more crash for each), and loads the suspects.
   * Returns the items quarantined by this crash (count reached 2).
   */
  recover(resource: ResourceId): Promise<EngineItem[]> {
    const key = toHex(resource);
    let running = this.#recovering.get(key);
    if (running === undefined) {
      running = this.#recover(key);
      this.#recovering.set(key, running);
    }
    return running;
  }

  async #recover(R: string): Promise<EngineItem[]> {
    const counts = new Map<string, number>();
    for (const m of await this.#storage.localMarks.list(`suspect:${R}:`))
      counts.set(m.key.slice(`suspect:${R}:`.length), Number(m.value));
    const leftover = await this.#storage.localMarks.get(this.#applying(R));
    const quarantined: EngineItem[] = [];
    if (leftover !== undefined) {
      const items = JSON.parse(leftover) as EngineItem[];
      for (const item of items) {
        const n = (counts.get(item) ?? 0) + 1;
        counts.set(item, n);
        if (n === 2) quarantined.push(item);
      }
      const r = await this.#storage.commit([
        ...items.map((item) => ({
          op: "put-local-mark" as const,
          key: `suspect:${R}:${item}`,
          value: String(counts.get(item)),
        })),
        { op: "put-local-mark", key: this.#applying(R), value: null },
      ]);
      if (!r.ok) throw new Error(`the crash record was not stored: ${r.reason}`);
    }
    this.#suspects.set(R, counts);
    return quarantined;
  }

  /** How often `item` crashed the engine (after recover()). */
  suspicion(resource: ResourceId, item: EngineItem): Suspicion {
    const n = this.#suspects.get(toHex(resource))?.get(item) ?? 0;
    return n >= 2 ? 2 : n === 1 ? 1 : 0;
  }

  /**
   * Runs `call` (the engine work on `items`) with the durable record in
   * place. Returns normally or with an ordinary error: the record is
   * removed, and suspects of count 1 that went through are cleared. On a
   * trap the record stays (the module is dead; the process must restart)
   * and the trap is rethrown.
   */
  async run<T>(resource: ResourceId, items: readonly EngineItem[], call: () => T | Promise<T>) {
    const R = toHex(resource);
    if (items.length === 0) return call();
    await this.#mark([
      { op: "put-local-mark", key: this.#applying(R), value: JSON.stringify(items) },
    ]);
    let result: T;
    try {
      result = await call();
    } catch (e) {
      if (isEngineTrap(e)) throw e;
      await this.#settled(R, items, false);
      throw e;
    }
    await this.#settled(R, items, true);
    return result;
  }

  async #settled(R: string, items: readonly EngineItem[], passed: boolean): Promise<void> {
    const counts = this.#suspects.get(R);
    const cleared = passed ? items.filter((item) => counts?.get(item) === 1) : [];
    for (const item of cleared) counts?.delete(item);
    await this.#mark([
      { op: "put-local-mark", key: this.#applying(R), value: null },
      ...cleared.map((item) => ({
        op: "put-local-mark" as const,
        key: `suspect:${R}:${item}`,
        value: null,
      })),
    ]);
  }

  async #mark(writes: Parameters<LfcpStorage["commit"]>[0]): Promise<void> {
    const r = await this.#storage.commit(writes);
    if (!r.ok) throw new Error(`the apply record was not stored: ${r.reason}`);
  }
}
