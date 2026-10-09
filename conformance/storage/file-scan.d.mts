/** The paths, relative to `dir`, of the files under it whose bytes contain `needle`. */
export function filesContaining(dir: string, needle: Uint8Array): string[];
