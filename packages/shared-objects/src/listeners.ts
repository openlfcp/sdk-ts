/**
 * Guarded change notifications for the Data Profile handlers
 * (REVIEW-20261015-03): every listener gets each event, and a listener that
 * throws never turns the operation that changed the model into a failure.
 * Its error goes to the handlers registered with onError, or, without one,
 * to the runtime's reportError where there is one (a browser, Electron);
 * else it is dropped. A handler that throws, or a failure while one is
 * being reported, is not reported again (no recursion). An engine trap is
 * the exception: it is thrown on once every listener has had the event, as
 * the client's SyncClient does, since the engine is dead.
 */

/**
 * A thrown value that looks like an engine trap (WebAssembly RuntimeError, a
 * terminated module): the rule of the client's isEngineTrap, which this
 * package cannot import.
 */
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

/** Listeners of events `E`, and the handlers of their failures `F`. */
export class GuardedListeners<E, F> {
  readonly #listeners = new Set<(event: E) => void>();
  readonly #errorHandlers = new Set<(failure: F) => void>();
  readonly #failure: (error: unknown, event: E) => F;
  #reporting = false;

  /** `failure` builds what a handler receives from the error and the event. */
  constructor(failure: (error: unknown, event: E) => F) {
    this.#failure = failure;
  }

  add(listener: (event: E) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  onError(handler: (failure: F) => void): () => void {
    this.#errorHandlers.add(handler);
    return () => this.#errorHandlers.delete(handler);
  }

  /** Delivers each event to every listener; see the module comment. */
  emit(events: readonly E[]): void {
    let trap: { readonly error: unknown } | undefined;
    const failed: { readonly error: unknown; readonly event: E }[] = [];
    for (const event of events)
      for (const l of [...this.#listeners])
        try {
          l(event);
        } catch (error) {
          if (isEngineTrap(error)) trap ??= { error };
          else failed.push({ error, event });
        }
    for (const { error, event } of failed) this.#report(error, event);
    if (trap !== undefined) throw trap.error;
  }

  #report(error: unknown, event: E): void {
    if (this.#reporting) return;
    this.#reporting = true;
    try {
      if (this.#errorHandlers.size === 0) {
        const report = (globalThis as { reportError?: (e: unknown) => void }).reportError;
        if (typeof report === "function") report(error);
        return;
      }
      const failure = this.#failure(error, event);
      for (const h of [...this.#errorHandlers])
        try {
          h(failure);
        } catch {
          // A failing error handler is not reported again (no recursion).
        }
    } catch {
      // reportError itself failed: nothing left to report to.
    } finally {
      this.#reporting = false;
    }
  }
}
