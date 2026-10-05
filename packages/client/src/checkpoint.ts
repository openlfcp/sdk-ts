import type { LfcpStorage, ProfileCheckpoint, StorageWrite } from "@openlfcp/storage";

/**
 * Persisting a Data Profile's local state (LFCP-036): an explicit,
 * caller-driven debounce. The sync engine calls noteChange() after merges
 * and local writes, and maybeFlush(now) on its own schedule; nothing here
 * keeps timers. A local write can carry the checkpoint in its own atomic
 * batch instead (write(), e.g. as createQueuedDataUnit's `also`).
 */

/** Anything that can describe its persistent state (e.g. SharedObjectsDataProfile). */
export interface CheckpointSource {
  checkpoint(): ProfileCheckpoint;
}

export class ProfileCheckpointer {
  readonly #storage: Pick<LfcpStorage, "commit">;
  readonly #source: CheckpointSource;
  readonly #minIntervalMs: number;
  #dirty = false;
  #lastFlushMs: number | null = null;

  constructor(
    storage: Pick<LfcpStorage, "commit">,
    source: CheckpointSource,
    options: { readonly minIntervalMs: number },
  ) {
    this.#storage = storage;
    this.#source = source;
    this.#minIntervalMs = options.minIntervalMs;
  }

  /** The profile state changed since the last checkpoint. */
  noteChange(): void {
    this.#dirty = true;
  }

  get dirty(): boolean {
    return this.#dirty;
  }

  /** Writes a checkpoint if something changed and `minIntervalMs` passed since the last one. */
  async maybeFlush(nowMs: number): Promise<boolean> {
    if (!this.#dirty) return false;
    if (this.#lastFlushMs !== null && nowMs - this.#lastFlushMs < this.#minIntervalMs) return false;
    await this.flush(nowMs);
    return true;
  }

  /** Writes a checkpoint now (e.g. before closing). */
  async flush(nowMs: number): Promise<void> {
    try {
      const r = await this.#storage.commit([this.write()]);
      if (!r.ok) throw new Error(`the checkpoint was not stored: ${r.reason}`);
    } catch (e) {
      this.#dirty = true;
      throw e;
    }
    this.#lastFlushMs = nowMs;
  }

  /**
   * The checkpoint as a write for another atomic batch. The state counts as
   * persisted once that batch commits; call it as the batch is built.
   */
  write(): StorageWrite {
    this.#dirty = false;
    return { op: "put-profile-checkpoint", checkpoint: this.#source.checkpoint() };
  }
}
