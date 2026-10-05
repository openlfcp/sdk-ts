// Types for spec.mjs (written by hand: sdk-ts has no Node type definitions).

export interface SpecLock {
  readonly repository: string;
  readonly tag: string;
  readonly commit: string;
}

export type Git = (dir: string, args: readonly string[]) => Uint8Array;

export interface Spec {
  readonly lock: SpecLock;
  readonly dir: string;
  read(path: string): Uint8Array;
  readText(path: string): string;
  readJson(path: string): unknown;
}

export const ROOT: string;
export function runGit(dir: string, args: readonly string[]): Uint8Array;
export function parseSpecLock(text: string, where?: string): SpecLock;
export function openSpec(options?: {
  readonly lock?: SpecLock;
  readonly specDir?: string;
  readonly git?: Git;
}): Spec;
export function log(line: string): void;
export function writeSummary(name: string, summary: unknown): string;
export function readRepoText(path: string): string;
