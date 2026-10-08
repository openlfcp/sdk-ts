// Types for rust-server.mjs (written by hand: sdk-ts has no Node type definitions).

export interface RunningRustServer {
  /** The server's WebSocket URL (ws://127.0.0.1:<port>/v1/ws). */
  readonly url: string;
  /** The server's state directory (its database and any other files it persists). */
  readonly stateDir: string;
  /** The running server's process ID (a new one after restart). */
  readonly pid: number;
  /** Every file under the state directory now, with its bytes (database, WAL, SHM, …). */
  files(): { readonly path: string; readonly bytes: Uint8Array }[];
  /** Everything the server logged so far (debug level: message types and codes, never payloads). */
  log(): string;
  /** SIGKILLs the server process (no clean shutdown); its state directory stays. */
  kill(): Promise<void>;
  /** SIGKILLs the server if it runs, then starts it again on the same port, config and state. */
  restart(): Promise<void>;
  /**
   * SIGKILLs the server, replaces its state directory with `files` (an
   * earlier files() copy: a restore from backup) and starts it again.
   */
  restore(files: readonly { readonly path: string; readonly bytes: Uint8Array }[]): Promise<void>;
  /** Stops the server and deletes its state directory. */
  stop(): Promise<void>;
}

export function startRustServer(): Promise<RunningRustServer | { readonly skip: string }>;
