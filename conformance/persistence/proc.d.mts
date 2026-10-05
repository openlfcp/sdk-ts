// Types for proc.mjs (written by hand: sdk-ts has no Node type definitions).

/** Runs writer-proc.mjs; with `killAt`, SIGKILLs it at that step. Resolves with its output lines. */
export function runWriter(args: readonly string[], killAt?: string): Promise<string[]>;
