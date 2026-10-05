#!/usr/bin/env node
// Enforces the sdk-ts package boundaries (LFCP-011).
//
//   graph            an @openlfcp/* dependency or import outside ALLOWED below
//   unknown-package  a workspace package missing from ALLOWED (decide its edges first)
//   obsidian         any dependency on, or import of, obsidian (anywhere)
//   node-import      a node:* or Node built-in import in a portable package
//   node-global      a Node-only global (process, Buffer, ...) in a portable package
//
// The portable packages must run in browsers and editors; Node-only code
// belongs in future *-node packages, which still have to be listed in ALLOWED.
//
//   node scripts/check-boundaries.mjs              check this repository
//   node scripts/check-boundaries.mjs --root DIR   check another workspace
//   node scripts/check-boundaries.mjs --self-test  run scripts/boundary-fixtures/*
//
// Each problem is one line: <file>:<line> <rule>: <detail>

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

// Allowed @openlfcp/* edges. Nothing may depend on client.
export const ALLOWED = {
  core: [],
  crypto: ["core"],
  wire: ["core"],
  storage: ["core"],
  "shared-objects": ["core"],
  client: ["core", "wire", "storage"],
};
const PORTABLE = new Set(["core", "crypto", "wire", "storage", "shared-objects", "client"]);
const NODE_GLOBALS = new Set([
  "process",
  "Buffer",
  "__dirname",
  "__filename",
  "require",
  "global",
  "setImmediate",
  "clearImmediate",
]);
const NODE_BUILTINS = new Set(builtinModules.filter((m) => !m.startsWith("_")));
const DEP_FIELDS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const SOURCE = /\.(ts|tsx|mts|cts|js|mjs|cjs)$/;

const isObsidian = (spec) => /(^|[@/])obsidian($|[-/])/i.test(spec);
const scopeName = (spec) => /^@openlfcp\/([^/]+)/.exec(spec)?.[1];
const isNodeBuiltin = (spec) => spec.startsWith("node:") || NODE_BUILTINS.has(spec.split("/")[0]);

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (name === "node_modules" || name === "dist") return [];
    return statSync(path).isDirectory() ? walk(path) : SOURCE.test(name) ? [path] : [];
  });
}

// Module specifiers and Node-global uses in one source file.
function scan(file) {
  const text = readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const specs = [];
  const globals = [];
  const line = (node) => sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
  const visit = (node) => {
    if (
      (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      specs.push([node.moduleSpecifier.text, line(node)]);
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference)
    ) {
      const e = node.moduleReference.expression;
      if (ts.isStringLiteral(e)) specs.push([e.text, line(node)]);
    } else if (
      ts.isCallExpression(node) &&
      node.arguments.length > 0 &&
      ts.isStringLiteralLike(node.arguments[0])
    ) {
      const callee = node.expression;
      if (
        callee.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(callee) && callee.text === "require")
      ) {
        specs.push([node.arguments[0].text, line(node)]);
      }
    } else if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteral(node.argument.literal)
    ) {
      specs.push([node.argument.literal.text, line(node)]);
    }
    if (ts.isIdentifier(node) && NODE_GLOBALS.has(node.text)) {
      const p = node.parent;
      const isMemberName =
        (ts.isPropertyAccessExpression(p) && p.name === node) ||
        (ts.isPropertyAssignment(p) && p.name === node);
      const isDeclaration =
        (ts.isVariableDeclaration(p) ||
          ts.isParameter(p) ||
          ts.isFunctionDeclaration(p) ||
          ts.isImportSpecifier(p)) &&
        p.name === node;
      if (!isMemberName && !isDeclaration) globals.push([node.text, line(node)]);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return { specs, globals };
}

export function check(root) {
  const problems = [];
  const rel = (p) => relative(root, p);
  const readPkg = (path) => JSON.parse(readFileSync(path, "utf8"));
  const depNames = (pkg) => DEP_FIELDS.flatMap((f) => Object.keys(pkg[f] ?? {}));

  const rootPkgPath = join(root, "package.json");
  if (existsSync(rootPkgPath)) {
    for (const dep of depNames(readPkg(rootPkgPath))) {
      if (isObsidian(dep)) problems.push(`package.json:1 obsidian: dependency ${dep}`);
    }
  }

  const packagesDir = join(root, "packages");
  const dirs = existsSync(packagesDir)
    ? readdirSync(packagesDir).filter((d) => existsSync(join(packagesDir, d, "package.json")))
    : [];
  for (const dir of dirs.sort()) {
    const pkgPath = join(packagesDir, dir, "package.json");
    const pkg = readPkg(pkgPath);
    const name = scopeName(pkg.name ?? "") ?? dir;
    const known = name in ALLOWED;
    if (!known)
      problems.push(
        `${rel(pkgPath)}:1 unknown-package: @openlfcp/${name} is not in the dependency graph`,
      );
    const allowed = new Set([name, ...(ALLOWED[name] ?? [])]);
    const portable = PORTABLE.has(name);

    for (const dep of depNames(pkg)) {
      if (isObsidian(dep)) problems.push(`${rel(pkgPath)}:1 obsidian: dependency ${dep}`);
      const target = scopeName(dep);
      if (known && target && !allowed.has(target))
        problems.push(`${rel(pkgPath)}:1 graph: @openlfcp/${name} may not depend on ${dep}`);
    }

    for (const file of walk(join(packagesDir, dir))) {
      const { specs, globals } = scan(file);
      for (const [spec, ln] of specs) {
        const where = `${rel(file)}:${ln}`;
        if (isObsidian(spec)) problems.push(`${where} obsidian: import of ${spec}`);
        const target = scopeName(spec);
        if (known && target && !allowed.has(target))
          problems.push(`${where} graph: @openlfcp/${name} may not import ${spec}`);
        if (portable && isNodeBuiltin(spec))
          problems.push(`${where} node-import: ${spec} in portable @openlfcp/${name}`);
      }
      if (portable) {
        for (const [g, ln] of globals)
          problems.push(`${rel(file)}:${ln} node-global: ${g} in portable @openlfcp/${name}`);
      }
    }
  }
  return problems;
}

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
let failed = false;

if (args.includes("--self-test")) {
  const fixtures = join(here, "boundary-fixtures");
  for (const name of readdirSync(fixtures).sort()) {
    const dir = join(fixtures, name);
    if (!statSync(dir).isDirectory()) continue;
    const want = readFileSync(join(dir, "expected.txt"), "utf8").split("\n").filter(Boolean).sort();
    const got = check(dir).sort();
    if (JSON.stringify(got) === JSON.stringify(want)) {
      console.log(`ok    ${name} (${want.length} expected problem(s))`);
    } else {
      failed = true;
      console.log(`FAIL  ${name}`);
      for (const l of want.filter((x) => !got.includes(x))) console.log(`      missing:    ${l}`);
      for (const l of got.filter((x) => !want.includes(x))) console.log(`      unexpected: ${l}`);
    }
  }
} else {
  const i = args.indexOf("--root");
  const root = i >= 0 ? args[i + 1] : join(here, "..");
  const problems = check(root);
  for (const p of problems) console.log(p);
  failed = problems.length > 0;
  console.log(`boundaries: ${problems.length} problem(s)`);
}
process.exit(failed ? 1 : 0);
