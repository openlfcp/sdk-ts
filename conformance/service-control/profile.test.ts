// SERVICE-CONTROL-TEST-VECTORS-01 conformance run (SERVICE-CONTROL-PROFILE-01
// §12): the official control Resource corpus at the spec commit pinned in
// spec.lock, through @openlfcp/shared-objects/service-control.

import type { PendingFile } from "../runner.js";
import { defineSuiteRun } from "../suite-run.js";
import { SERVICE_CONTROL_HANDLERS } from "./handlers.js";
import pending from "./pending.json" with { type: "json" };

await defineSuiteRun(
  "test-vectors/service-control-01/SERVICE-CONTROL-TEST-VECTORS-01.json",
  "service-control-test-vectors-01",
  SERVICE_CONTROL_HANDLERS,
  pending as PendingFile,
);
