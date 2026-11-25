// Types for cold-client.mjs (written by hand: sdk-ts has no Node type definitions).

export interface ColdClientFigures {
  readonly coldConnectMs: number;
  readonly cold: {
    readonly fromSnapshot: number;
    readonly tail: number;
    readonly validate: number;
    readonly creatorsOf: number;
    readonly requestHistory: number;
  };
  /** The child with the Snapshot and the units in hand, before it builds the replica. */
  readonly baseRssMiB: number;
  /** The child's peak resident set size over its whole run. */
  readonly peakRssMiB: number;
  readonly heapMiB: number;
  readonly tailUnits: number;
}

/**
 * Runs a cold client on `snapshot` and `units` (the history, its last `tail` units after the
 * Snapshot) in a process of its own and returns its figures.
 */
export function measureColdClient(
  snapshot: Uint8Array,
  units: readonly {
    readonly signer: Uint8Array;
    readonly actorSeq: number;
    readonly signerClass: string;
    readonly bytes: Uint8Array;
  }[],
  tail: number,
  options: {
    readonly resource: Uint8Array;
    readonly root: Uint8Array;
    readonly genesisSigner: Uint8Array;
  },
): ColdClientFigures;
