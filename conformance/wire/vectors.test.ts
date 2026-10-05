// LFCP-TEST-VECTORS-01 conformance run (LFCP-017): the official suite at the
// spec commit pinned in spec.lock, through the sdk-ts Wire handlers.

import type { PendingFile } from "../runner.js";
import { defineSuiteRun } from "../suite-run.js";
import { WIRE_HANDLERS } from "./handlers.js";
import pending from "./pending.json" with { type: "json" };

defineSuiteRun(
  "test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json",
  "lfcp-test-vectors-01",
  WIRE_HANDLERS,
  pending as PendingFile,
);
