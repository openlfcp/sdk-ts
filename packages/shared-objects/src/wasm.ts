import * as A from "@automerge/automerge";

/** What initializing Automerge needs (injectable for tests). */
export interface AutomergeWasmHooks {
  readonly isInitialized: () => boolean;
  readonly loadBase64: () => Promise<string>;
  readonly initialize: (base64: string) => Promise<void>;
}

/**
 * An idempotent, concurrency-safe initializer: concurrent callers share one
 * in-flight promise; a failure clears it so a later call can retry.
 */
export function automergeInitializer(hooks: AutomergeWasmHooks): () => Promise<void> {
  let inFlight: Promise<void> | null = null;
  return () => {
    if (hooks.isInitialized()) return Promise.resolve();
    inFlight ??= (async () => {
      try {
        await hooks.initialize(await hooks.loadBase64());
      } catch (e) {
        inFlight = null;
        throw e;
      }
    })();
    return inFlight;
  };
}

/**
 * Makes sure Automerge's WebAssembly is ready. Every build of
 * `@automerge/automerge` except `/slim` initializes it on import, so this is
 * a no-op there. A host that aliases `@automerge/automerge` to its `/slim`
 * entry (e.g. a renderer where compiling 3.5 MB of wasm synchronously on the
 * main thread is refused, as Chromium does above 4 KB) awaits this once
 * before using this package: it loads the base64 wasm through a dynamic
 * import and compiles it asynchronously. Idempotent and safe to call
 * concurrently; a failed attempt can be retried.
 */
export const initializeAutomerge: () => Promise<void> = automergeInitializer({
  isInitialized: () => A.isWasmInitialized(),
  loadBase64: async () =>
    (await import("@automerge/automerge/automerge.wasm.base64")).automergeWasmBase64,
  initialize: (base64) => A.initializeBase64Wasm(base64),
});

/** Whether Automerge's WebAssembly is ready (always, except on `/slim` before initializeAutomerge). */
export const isAutomergeInitialized = (): boolean => A.isWasmInitialized();
