// FileSecretStore file names (503, spike B-001 BUG-1): a file was named by
// the hex of the whole SecretRef, so a reference over 124 characters (a
// pending-DEK reference of the identity flows is about 131) could not be
// stored or even looked up: ENAMETOOLONG. Now the name is the SHA-256 of the
// reference; files under the old name are read and moved.

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pendingDekRef } from "@openlfcp/client";
import { generateResourceId } from "@openlfcp/core";
import { type SecretRef, secretRef } from "@openlfcp/storage";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileSecretStore } from "../src/index.js";
import { legacyFileName, secretFileName } from "../src/secrets.js";

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "lfcp-secret-names-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const longest = secretRef("resource-dek", "a".repeat(200));
const bytes = (n: number) => Uint8Array.from({ length: 32 }, (_, i) => (n + i) & 0xff);
const files = () => readdirSync(dir).sort();

describe("FileSecretStore file names", () => {
  it("stores, reads and deletes the longest reference secretRef allows", async () => {
    const store = new FileSecretStore(dir);
    await store.put(longest, bytes(1));
    expect(await store.get(longest)).toEqual(bytes(1));
    await store.delete(longest);
    expect(await store.get(longest)).toBeUndefined();
    expect(files()).toEqual([]);
  });

  it("stores the pending-DEK reference of a pairing approval (the B-001 case)", async () => {
    const store = new FileSecretStore(dir);
    const ref = pendingDekRef(generateResourceId(), "pairing-approval.0123456789abcdef");
    expect(await store.get(ref)).toBeUndefined();
    await store.put(ref, bytes(2));
    expect(await store.get(ref)).toEqual(bytes(2));
  });

  it("names every file with 64 lowercase hex digits and .secret: short, and valid on Windows", async () => {
    const store = new FileSecretStore(dir);
    const refs: SecretRef[] = [
      longest,
      secretRef("invitation-secret", "x"),
      secretRef("local-state-key", "A.b_c-9"),
    ];
    for (const [i, ref] of refs.entries()) await store.put(ref, bytes(i));
    for (const name of files()) expect(name).toMatch(/^[0-9a-f]{64}\.secret$/);
    expect(files()).toEqual(refs.map(secretFileName).sort());
  });

  it("reads a file under the legacy name and moves it to the new one", async () => {
    const ref = secretRef("resource-dek", "00ff.1");
    const legacy = legacyFileName(ref) as string;
    writeFileSync(join(dir, legacy), bytes(3), { mode: 0o600 });
    const store = new FileSecretStore(dir);
    expect(await store.get(ref)).toEqual(bytes(3));
    expect(files()).toEqual([secretFileName(ref)]);
    expect(Uint8Array.from(readFileSync(join(dir, secretFileName(ref))))).toEqual(bytes(3));
    expect(await store.get(ref)).toEqual(bytes(3));
  });

  it("a write replaces a legacy file; the new name wins while both exist; delete removes both", async () => {
    const ref = secretRef("resource-dek", "beef.2");
    const legacy = legacyFileName(ref) as string;
    const store = new FileSecretStore(dir);
    writeFileSync(join(dir, legacy), bytes(4));
    await store.put(ref, bytes(5));
    expect(files()).toEqual([secretFileName(ref)]);
    // A crash between the rename and the legacy unlink leaves both: the new value is read.
    writeFileSync(join(dir, legacy), bytes(4));
    expect(await store.get(ref)).toEqual(bytes(5));
    await store.delete(ref);
    expect(existsSync(join(dir, legacy))).toBe(false);
    expect(files()).toEqual([]);
    expect(await store.get(ref)).toBeUndefined();
  });

  it("has no legacy name for a reference too long to have been stored", () => {
    expect(legacyFileName(longest)).toBeUndefined();
    expect(legacyFileName(secretRef("resource-dek", "a".repeat(99)))).toBeDefined();
    expect(legacyFileName(secretRef("resource-dek", "a".repeat(100)))).toBeUndefined();
  });
});

// Review #26 (r2): two processes on one directory, and the order of deletes on disk.
describe("FileSecretStore migration against another writer", () => {
  const ref = secretRef("resource-dek", "cafe.3");

  it("a put that lands while a read migrates the legacy file wins", async () => {
    writeFileSync(join(dir, legacyFileName(ref) as string), bytes(6), { mode: 0o600 });
    const other = new FileSecretStore(dir);
    // The other process writes after this one decided to migrate, before it moves the file.
    const store = new FileSecretStore(dir, {
      beforeMigration: () => void other.put(ref, bytes(7)),
    });
    expect(await store.get(ref)).toEqual(bytes(7));
    expect(await new FileSecretStore(dir).get(ref)).toEqual(bytes(7));
    expect(files()).toEqual([secretFileName(ref)]);
  });

  it("a delete that lands while a read migrates is not undone", async () => {
    writeFileSync(join(dir, legacyFileName(ref) as string), bytes(8), { mode: 0o600 });
    const other = new FileSecretStore(dir);
    const store = new FileSecretStore(dir, {
      beforeMigration: () => void other.delete(ref),
    });
    expect(await store.get(ref)).toBeUndefined();
    expect(files()).toEqual([]);
  });

  it("delete makes the legacy unlink durable before it removes the new name", async () => {
    const legacy = join(dir, legacyFileName(ref) as string);
    const current = join(dir, secretFileName(ref));
    const seen: [boolean, boolean][] = [];
    const store = new FileSecretStore(dir, {
      directorySync: {
        openSync: (p, f) => {
          seen.push([existsSync(legacy), existsSync(current)]);
          return openSync(p, f);
        },
        fsyncSync,
        closeSync,
      },
    });
    await store.put(ref, bytes(9));
    writeFileSync(legacy, bytes(1), { mode: 0o600 });
    seen.length = 0;
    await store.delete(ref);
    // A directory fsync while the legacy name is gone and the new one still there.
    expect(seen).toContainEqual([false, true]);
    expect(seen.at(-1)).toEqual([false, false]);
  });
});
