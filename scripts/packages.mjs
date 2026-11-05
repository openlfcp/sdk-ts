// The @openlfcp/* packages, in publish order: each package after everything
// it depends on (release-check.mjs checks it; release.yml and
// registry-check.mjs publish and verify in this order).
export const PUBLISH_ORDER = [
  "core",
  "crypto",
  "storage",
  "wire",
  "storage-idb",
  "shared-objects",
  "client",
  // After client: it hosts the headless `lfcp-node pair` (LFCP-04-412).
  "storage-node",
];
