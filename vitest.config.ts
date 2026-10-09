import { defineConfig } from "vitest/config";

// The engine-trap test (conformance/security) traps the Automerge engine for
// real in child processes: each trapping start costs about 20 s of CPU, and
// under the load of the other test files it once ran past its timeout
// (POST-010). It is a project of its own, run after every other file is done
// (sequence.groupOrder), so it never competes with them for CPU.
const ENGINE_TRAP = "conformance/security/engine-trap.test.ts";

export default defineConfig({
  test: {
    // Fail on test.todo outside todo-allowlist.json (scripts/todo-guard.mjs).
    reporters: ["default", "./scripts/todo-guard.mjs"],
    projects: [
      {
        extends: true,
        test: {
          name: "sdk-ts",
          include: ["packages/*/test/**/*.test.ts", "conformance/**/*.test.ts"],
          exclude: [ENGINE_TRAP, "**/node_modules/**"],
        },
      },
      {
        extends: true,
        test: {
          name: "engine-trap",
          include: [ENGINE_TRAP],
          sequence: { groupOrder: 1 },
        },
      },
    ],
  },
});
