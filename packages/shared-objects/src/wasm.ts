import * as A from "@automerge/automerge";

/**
 * Makes sure Automerge's WebAssembly is ready. Every build of
 * `@automerge/automerge` except `/slim` initializes it on import, so this is
 * a no-op there. A host that aliases `@automerge/automerge` to its `/slim`
 * entry (e.g. a renderer where compiling 3.5 MB of wasm synchronously on the
 * main thread is refused, as Chromium does above 4 KB) awaits this once
 * before using this package: it loads the base64 wasm through a dynamic
 * import and compiles it asynchronously.
 */
export async function initializeAutomerge(): Promise<void> {
  if (A.isWasmInitialized()) return;
  const { automergeWasmBase64 } = await import("@automerge/automerge/automerge.wasm.base64");
  await A.initializeBase64Wasm(automergeWasmBase64);
}

/** Whether Automerge's WebAssembly is ready (always, except on `/slim` before initializeAutomerge). */
export const isAutomergeInitialized = (): boolean => A.isWasmInitialized();
