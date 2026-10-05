// SHARED-OBJECTS-TEST-VECTORS-01 conformance run (LFCP-030): the official
// suite at the spec commit pinned in spec.lock, through the sdk-ts Shared
// Objects handlers.

import type { PendingFile } from "../runner.js";
import { defineSuiteRun } from "../suite-run.js";
import { SHARED_OBJECTS_HANDLERS } from "./handlers.js";
import pending from "./pending.json" with { type: "json" };

await defineSuiteRun(
  "test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json",
  "shared-objects-test-vectors-01",
  SHARED_OBJECTS_HANDLERS,
  pending as PendingFile,
);
