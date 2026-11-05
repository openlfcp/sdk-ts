// IDENTITY-FLOW-FIXTURES-01 conformance run (LFCP-04-412): every flow
// fixture step by step at the spec commit pinned in spec.lock, with its
// outcome exported as identity-flows.json (lfcp-identity-outcomes/1) when
// LFCP_IDENTITY_REPORT_DIR is set, for the differential run against sdk-rs
// (scripts/identity-differential.mjs).

import type { PendingFile } from "../runner.js";
import { defineSuiteRun } from "../suite-run.js";
import { FLOW_FIXTURES } from "./corpus.js";
import { IDENTITY_FLOW_HANDLERS } from "./flow-handlers.js";
import pending from "./flows-pending.json" with { type: "json" };

await defineSuiteRun(
  FLOW_FIXTURES,
  "identity-flow-fixtures-01",
  IDENTITY_FLOW_HANDLERS,
  pending as PendingFile,
  {
    file: "identity-flows.json",
  },
);
