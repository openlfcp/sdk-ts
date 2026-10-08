// Types for spec.mjs (written by hand: sdk-ts has no Node type definitions).

export interface SpecLock {
  readonly repository: string;
  readonly tag: string;
  readonly commit: string;
}

export type Git = (dir: string, args: readonly string[]) => Uint8Array;

export interface SpecSectionsLock {
  readonly repository: string;
  readonly commit: string;
  readonly status: "dev-pin-pre-baseline";
}

export interface Spec<L = SpecLock> {
  readonly lock: L;
  readonly dir: string;
  /** The entry names of a directory at the locked commit, sorted. */
  list(dir: string): string[];
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
export const DEV_PIN_STATUS: "dev-pin-pre-baseline";
export const SECTIONS_PATHS: readonly string[];
export function parseSpecSectionsLock(text: string, where?: string): SpecSectionsLock;
export function openSpecSections(options?: {
  readonly lock?: SpecSectionsLock;
  readonly specDir?: string;
  readonly git?: Git;
}): Spec<SpecSectionsLock>;
export function log(line: string): void;
export function writeSummary(name: string, summary: unknown): string;
export function readRepoText(path: string): string;
