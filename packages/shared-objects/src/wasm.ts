import * as A from "@automerge/automerge";

// Every runtime this package supports has atob (browsers, workers, Node 16+).
declare const atob: (data: string) => string;

/** What initializing Automerge needs (injectable for tests). */
export interface AutomergeWasmHooks {
  readonly isInitialized: () => boolean;
  readonly loadBase64: () => Promise<string>;
  readonly initialize: (wasm: Uint8Array) => Promise<void>;
}

/**
 * Standard base64 to bytes, fast: Uint8Array.fromBase64 where the runtime
 * has it, else atob and a plain loop. Automerge's own initializeBase64Wasm
 * decodes with Uint8Array.from(atob(s), callback), which takes about 200 ms
 * of main-thread time for its 3.5 MB wasm (measured in Node 24, LFCP-059);
 * this takes under 10 ms.
 */
export function decodeBase64(text: string): Uint8Array {
  const native = (Uint8Array as { fromBase64?: (s: string) => Uint8Array }).fromBase64;
  if (native !== undefined) return native(text);
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
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
        await hooks.initialize(decodeBase64(await hooks.loadBase64()));
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
 * import, decodes it quickly and compiles it asynchronously. Idempotent and
 * safe to call concurrently; a failed attempt can be retried.
 */
export const initializeAutomerge: () => Promise<void> = automergeInitializer({
  isInitialized: () => A.isWasmInitialized(),
  loadBase64: async () =>
    (await import("@automerge/automerge/automerge.wasm.base64")).automergeWasmBase64,
  // initializeWasm compiles and instantiates asynchronously (WebAssembly.instantiate).
  initialize: (wasm) => A.initializeWasm(wasm),
});

/** Whether Automerge's WebAssembly is ready (always, except on `/slim` before initializeAutomerge). */
export const isAutomergeInitialized = (): boolean => A.isWasmInitialized();
