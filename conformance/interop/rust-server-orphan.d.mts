// Types for rust-server-orphan.mjs (written by hand: sdk-ts has no Node type definitions).

export type OrphanCheck =
  | { readonly skip: string }
  | {
      /** The server ran while its parent did. */
      readonly aliveBefore: boolean;
      /** The server still ran `withinMs` after its parent was SIGKILLed. */
      readonly serverAlive: boolean;
      /** The server's temporary directory was still there then. */
      readonly dirExists: boolean;
    };

/** Starts a parent process that starts a server, SIGKILLs the parent, and waits up to `withinMs`. */
export function checkOrphan(withinMs: number): Promise<OrphanCheck>;
