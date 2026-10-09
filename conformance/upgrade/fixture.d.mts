export function copySqliteFixture(dir: string): { db: string; secrets: string };
export function readIdbFixture(): {
  version: number;
  stores: Record<string, [unknown, unknown][]>;
  secrets: [string, Uint8Array][];
};
