// Types for spec3.mjs (written by hand: sdk-ts has no Node type definitions).
export const IDENTITY_SPEC: {
  readonly repository: string;
  readonly ref: string;
  readonly commit: string;
};
export const WIRE_IDENTITY: string;
export const PROFILE_IDENTITY: string;
export const FLOW_FIXTURES: string;
export function readIdentityJson(path: string): unknown;
