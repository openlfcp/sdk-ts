// IDENTITY-PROFILE-TEST-VECTORS-01 conformance run (LFCP-04-409b): the
// official identity profile corpus at the spec commit pinned in spec.lock,
// through @openlfcp/shared-objects/identity, with its outcome exported as
// identity-profile.json (lfcp-identity-outcomes/1) when
// LFCP_IDENTITY_REPORT_DIR is set (LFCP-04-412).

import type { PendingFile } from "../runner.js";
import { defineSuiteRun } from "../suite-run.js";
import { IDENTITY_PROFILE_HANDLERS } from "./profile-handlers.js";
import pending from "./profile-pending.json" with { type: "json" };

await defineSuiteRun(
  "test-vectors/identity-01/IDENTITY-PROFILE-TEST-VECTORS-01.json",
  "identity-profile-test-vectors-01",
  IDENTITY_PROFILE_HANDLERS,
  pending as PendingFile,
  { file: "identity-profile.json" },
);
