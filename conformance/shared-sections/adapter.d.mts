// Types for adapter.mjs (written by hand: sdk-ts has no Node type definitions).

export function runCase(input: {
  readonly id: string;
  readonly profile: string;
  readonly identities: unknown;
  readonly base_snapshot: unknown;
  readonly base_changes: readonly unknown[];
  readonly branches: { readonly A: readonly unknown[]; readonly B: readonly unknown[] };
  readonly after_merge: readonly unknown[];
  readonly delivery?: "normal" | "reverse" | "checkpoint";
}): Promise<Record<string, unknown>>;
