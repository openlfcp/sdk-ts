// Types for pair-cli.mjs (written by hand: sdk-ts has no Node type definitions).

export interface PairCli {
  /** Everything the command printed so far. */
  output(): string;
  stderr(): string;
  readonly exited: Promise<{ readonly code: number | null; readonly signal: string | null }>;
  kill(): Promise<void>;
}

/** A fresh state directory for one installation. */
export function stateDir(): string;
export function removeDir(dir: string): void;
/** `lfcp-node pair <args>` with `link` on standard input. */
export function startPairCli(args: readonly string[], link?: string): PairCli;
