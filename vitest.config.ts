import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/test/**/*.test.ts", "conformance/**/*.test.ts"],
    // Fail on test.todo outside todo-allowlist.json (scripts/todo-guard.mjs).
    reporters: ["default", "./scripts/todo-guard.mjs"],
  },
});
