// A reader for the subset of CBOR diagnostic notation (RFC 8949 §8, RFC
// 8610 Appendix G) used by the spec's hand-built CDDL fixtures: maps,
// arrays, integers, h'...' byte strings, "..." text strings, true, false,
// null and /.../ comments. Anything else is an error, never a guess.

import { type CborKey, type CborValue, cborMap } from "@openlfcp/wire/cbor";

export function parseDiag(text: string): CborValue {
  let i = 0;
  const fail = (why: string): never => {
    throw new Error(`diagnostic notation, offset ${i}: ${why}`);
  };
  const skip = () => {
    for (;;) {
      while (i < text.length && /\s/.test(text[i] as string)) i++;
      if (text[i] !== "/") return;
      const end = text.indexOf("/", i + 1);
      if (end < 0) fail("unterminated comment");
      i = end + 1;
    }
  };
  const expect = (c: string) => {
    skip();
    if (text[i] !== c) fail(`expected "${c}"`);
    i++;
  };
  const value = (): CborValue => {
    skip();
    const c = text[i];
    if (c === "{" || c === "[") {
      i++;
      const close = c === "{" ? "}" : "]";
      const items: CborValue[] = [];
      const entries: [CborKey, CborValue][] = [];
      skip();
      while (text[i] !== close) {
        if (c === "{") {
          const k = value();
          expect(":");
          entries.push([k as CborKey, value()]);
        } else items.push(value());
        skip();
        if (text[i] === ",") i++;
        else if (text[i] !== close) fail(`expected "," or "${close}"`);
        skip();
      }
      i++;
      return c === "{" ? cborMap(entries) : items;
    }
    if (c === '"') {
      const end = text.indexOf('"', i + 1);
      if (end < 0) fail("unterminated text string");
      const s = text.slice(i + 1, end);
      if (s.includes("\\")) fail("escapes are not supported");
      i = end + 1;
      return s;
    }
    if (text.startsWith("h'", i)) {
      const end = text.indexOf("'", i + 2);
      if (end < 0) fail("unterminated byte string");
      const hex = text.slice(i + 2, end).replace(/\s/g, "");
      if (!/^([0-9a-fA-F]{2})*$/.test(hex)) fail("bad hex in byte string");
      i = end + 1;
      return Uint8Array.from(hex.match(/../g) ?? [], (b) => Number.parseInt(b, 16));
    }
    for (const [word, v] of [
      ["true", true],
      ["false", false],
      ["null", null],
    ] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    }
    const m = /^-?\d+/.exec(text.slice(i));
    if (m === null) return fail("unsupported item");
    i += m[0].length;
    const n = BigInt(m[0]);
    return Number.isSafeInteger(Number(n)) ? Number(n) : n;
  };
  const result = value();
  skip();
  if (i !== text.length) fail("trailing text");
  return result;
}
