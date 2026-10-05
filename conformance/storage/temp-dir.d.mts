// Types for temp-dir.mjs (written by hand: sdk-ts has no Node type definitions).

export function makeTempDir(prefix: string): string;
export function removeTempDir(dir: string): void;
export function inDir(dir: string, name: string): string;
