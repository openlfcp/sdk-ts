import { mkdirSync } from "node:fs";
import { join } from "node:path";

export const dir = (base: string): string => {
  mkdirSync(join(base, "x"), { recursive: true });
  return process.cwd();
};
