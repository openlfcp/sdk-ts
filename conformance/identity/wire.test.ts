// LFCP-IDENTITY-TEST-VECTORS-01 conformance run (LFCP-04-412): every case of
// the wire identity corpus at the spec commit pinned in spec.lock, with its
// outcome exported as identity-wire.json (lfcp-identity-outcomes/1) when
// LFCP_IDENTITY_REPORT_DIR is set, for the differential run against sdk-rs
// (scripts/identity-differential.mjs).

import type { PendingFile } from "../runner.js";
import { defineSuiteRun } from "../suite-run.js";
import { WIRE_IDENTITY } from "./corpus.js";
import { IDENTITY_WIRE_HANDLERS } from "./wire-handlers.js";
import pending from "./wire-pending.json" with { type: "json" };

await defineSuiteRun(
  WIRE_IDENTITY,
  "identity-wire-test-vectors-01",
  IDENTITY_WIRE_HANDLERS,
  pending as PendingFile,
  { file: "identity-wire.json" },
);
