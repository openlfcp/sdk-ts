// UTF-8 through the WHATWG TextEncoder/TextDecoder globals, which browsers,
// Node.js and editors all provide. Declared here so the package needs no
// DOM or Node type library.
interface Utf8Encoder {
  encode(text: string): Uint8Array;
}
interface Utf8Decoder {
  decode(bytes: Uint8Array): string;
}
const g = globalThis as unknown as {
  TextEncoder: new () => Utf8Encoder;
  TextDecoder: new (label: string, options: { fatal: boolean }) => Utf8Decoder;
};

export const utf8Encoder: Utf8Encoder = new g.TextEncoder();
/** Throws on malformed UTF-8 instead of inserting U+FFFD. */
export const strictUtf8Decoder: Utf8Decoder = new g.TextDecoder("utf-8", { fatal: true });
