# @openlfcp/client

An LFCP client on top of the other packages: the WebSocket session (`SyncClient`), Control and Data Plane synchronization, the outbound queue, applying received units to a Data Profile (`DataUnitApplier`) with the crash-loop breaker, invitations, Snapshots and storage helpers.

```sh
npm install @openlfcp/client@next
```

ESM only; Node.js 24 or later (browsers and Electron for every package except `@openlfcp/storage-node`).

## Scope

Part of the OpenLFCP TypeScript SDK, which implements the OpenLFCP MVP 0.1
subset of [LFCP-WIRE-01](https://github.com/openlfcp/spec/blob/main/wire/LFCP-WIRE-01.md)
at `mvp-0.1-baseline.8`, not every deferred WIRE-01 feature. It does not
claim full LFCP-WIRE-01 conformance. This is the MVP 0.1 release
(`0.1.0`, npm dist-tag `latest`). Until 1.0, minor versions may change APIs.

## Links

- Specification: [openlfcp/spec](https://github.com/openlfcp/spec)
- Source and the other SDK packages: [openlfcp/sdk-ts](https://github.com/openlfcp/sdk-ts)
- Issues: [openlfcp/sdk-ts/issues](https://github.com/openlfcp/sdk-ts/issues)

## License

Apache-2.0. See [LICENSE](LICENSE).
