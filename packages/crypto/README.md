# @openlfcp/crypto

The cryptography of LFCP on audited primitives: SHA-256, Ed25519 signatures (strict verification), X25519, HKDF, ChaCha20-Poly1305 and HPKE for Key Packages, Resource DEKs and their commitments. It is the only package that uses `@noble/*` and `hpke` directly.

```sh
npm install @openlfcp/crypto@next
```

ESM only; Node.js 24 or later (browsers and Electron for every package except `@openlfcp/storage-node`).

## Scope

Part of the OpenLFCP TypeScript SDK, which implements the OpenLFCP MVP 0.1
subset of [LFCP-WIRE-01](https://github.com/openlfcp/spec/blob/main/wire/LFCP-WIRE-01.md)
at `mvp-0.1-baseline.8`, not every deferred WIRE-01 feature. It does not
claim full LFCP-WIRE-01 conformance. This is a release candidate
(`0.1.0-rc.1`, npm dist-tag `next`): APIs may still change.

## Links

- Specification: [openlfcp/spec](https://github.com/openlfcp/spec)
- Source and the other SDK packages: [openlfcp/sdk-ts](https://github.com/openlfcp/sdk-ts)
- Issues: [openlfcp/sdk-ts/issues](https://github.com/openlfcp/sdk-ts/issues)

## License

Apache-2.0. See [LICENSE](LICENSE).
