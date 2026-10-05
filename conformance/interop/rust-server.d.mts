// Types for rust-server.mjs (written by hand: sdk-ts has no Node type definitions).

export interface RunningRustServer {
  /** The server's WebSocket URL (ws://127.0.0.1:<port>/v1/ws). */
  readonly url: string;
  /** Everything the server logged so far (debug level: message types and codes, never payloads). */
  log(): string;
  /** Stops the server and deletes its state directory. */
  stop(): Promise<void>;
}

export function startRustServer(): Promise<RunningRustServer | { readonly skip: string }>;
