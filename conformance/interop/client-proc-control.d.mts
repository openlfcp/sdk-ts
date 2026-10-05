// Types for client-proc-control.mjs (written by hand: sdk-ts has no Node type definitions).

export interface ClientEvent {
  readonly t: string;
  readonly [field: string]: unknown;
}

export interface ClientProc {
  /** Every JSON line the child printed so far. */
  readonly events: ClientEvent[];
  stderr(): string;
  send(line: string): void;
  /** SIGKILL, then wait for the exit. */
  kill(): Promise<void>;
  alive(): boolean;
}

export function startClientProc(args: readonly string[]): ClientProc;
