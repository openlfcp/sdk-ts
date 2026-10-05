// A Vitest reporter that fails the run on test.todo (LFCP-072): a todo is
// accepted only when todo-allowlist.json lists it, as a feature MVP 0.1
// defers, with its entry in `.github: docs/release/deferred-wire-01-features.md`.
// An allowlist entry that matches no todo fails too, so the list never
// goes stale. Same spirit as the plugin's fail-on-skip.
// JavaScript: sdk-ts has no Node type definitions (as conformance/*.mjs).

import { readFileSync } from "node:fs";

/** @returns {{ name: string, deferred: string }[]} */
function allowlist() {
  const list = JSON.parse(readFileSync(new URL("../todo-allowlist.json", import.meta.url), "utf8"));
  for (const a of list.todos)
    if (!/deferred-wire-01-features\.md/.test(a.deferred ?? ""))
      throw new Error(`todo-allowlist.json: "${a.name}" names no deferred-features entry`);
  return list.todos;
}

export default class TodoGuard {
  /** @param {ReadonlyArray<{ children: { allTests(): Iterable<{ fullName: string, options: { mode: string } }> } }>} modules */
  onTestRunEnd(modules) {
    const allowed = allowlist();
    const used = new Set();
    const unexpected = [];
    for (const m of modules)
      for (const t of m.children.allTests()) {
        if (t.options.mode !== "todo") continue;
        const entry = allowed.find((a) => t.fullName.includes(a.name));
        if (entry === undefined) unexpected.push(t.fullName);
        else used.add(entry);
      }
    const stale = allowed.filter((a) => !used.has(a)).map((a) => a.name);
    if (unexpected.length === 0 && stale.length === 0) return;
    const lines = [
      ...unexpected.map((n) => `todo not in todo-allowlist.json: ${n}`),
      ...stale.map((n) => `todo-allowlist.json entry matches no todo: ${n}`),
    ];
    process.stderr.write(`\ntodo guard (LFCP-072):\n${lines.map((l) => `  ${l}`).join("\n")}\n`);
    process.exitCode = 1;
  }
}
