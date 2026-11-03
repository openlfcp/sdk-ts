import * as A from "@automerge/automerge";
import { toBase64url } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { validateIdentity } from "../src/identity/index.js";
import { principalRef } from "../src/values.js";
import {
  actor,
  type Doc,
  device,
  edit,
  filled,
  otherWriter,
  pairingWriter,
  personalWriter,
  request,
  resourceRef,
  root,
  rootWriter,
  S,
  secondDevice,
  U,
} from "./support/identity.js";

function base() {
  return edit(
    filled().doc,
    (d) => {
      d.requests[device.key] = request();
    },
    pairingWriter,
  );
}
function raw(doc: A.Doc<Doc>, fn: (d: Doc) => void, writer = personalWriter) {
  return A.change(A.clone(doc, { actor: actor(writer) }), { time: 0 }, fn);
}
const check = (fn: (d: Doc) => void) => validateIdentity(raw(base(), fn), root);

describe("identity state / ID-05 (§4)", () => {
  it("request_valid", () => {
    const v = validateIdentity(base(), root);
    expect(v.problems).toEqual([]);
    expect(v.requests[device.key]).toEqual({
      descriptor: device.text,
      pairing: principalRef(pairingWriter.signer),
      label: "phone",
      kind: 0,
    });
    expect(v.devices[device.key]).toEqual({ label: "phone", kind: 0 });
    expect(v.roster[resourceRef]?.endpoints).toEqual(["https://example.test"]);
  });

  it("request_service_valid", () => {
    const v = check((d) => {
      d.requests[device.key].kind = U(1);
      d.requests[device.key].scope = [S(resourceRef)];
    });
    expect(v.problems).toEqual([]);
    expect(v.requests[device.key]?.scope).toEqual([resourceRef]);
  });

  const cases: [string, (d: Doc) => void, string][] = [
    [
      "request_service_without_scope",
      (d) => {
        d.requests[device.key].kind = U(1);
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "request_personal_with_scope",
      (d) => {
        d.requests[device.key].scope = [S(resourceRef)];
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "request_scope_bad_ref",
      (d) => {
        d.requests[device.key].kind = U(1);
        d.requests[device.key].scope = [S("bad")];
      },
      "INVALID_RESOURCE_REF",
    ],
    [
      "scope empty",
      (d) => {
        d.requests[device.key].kind = U(1);
        d.requests[device.key].scope = [];
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "scope repeats",
      (d) => {
        d.requests[device.key].kind = U(1);
        d.requests[device.key].scope = [S(resourceRef), S(resourceRef)];
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "scope too long",
      (d) => {
        d.requests[device.key].kind = U(1);
        d.requests[device.key].scope = Array.from({ length: 65 }, (_, i) =>
          S(toBase64url(new Uint8Array(32).fill(i))),
        );
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "request_key_descriptor_mismatch",
      (d) => {
        d.requests[device.key].descriptor = S(secondDevice.text);
      },
      "INVALID_DESCRIPTOR",
    ],
    [
      "request_bad_descriptor",
      (d) => {
        d.requests[device.key].descriptor = S("aGVsbG8");
      },
      "INVALID_DESCRIPTOR",
    ],
    [
      "descriptor type",
      (d) => {
        d.requests[device.key].descriptor = false;
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "request_missing_label",
      (d) => {
        delete d.requests[device.key].label;
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "request_kind_2",
      (d) => {
        d.requests[device.key].kind = U(2);
      },
      "INVALID_ENUM_VALUE",
    ],
    [
      "kind signed integer",
      (d) => {
        d.requests[device.key].kind = new A.Int(1);
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "request_bad_timestamp",
      (d) => {
        d.requests[device.key].requested_at = S("2026-11-04T01:00:00+00:00");
      },
      "INVALID_TIMESTAMP",
    ],
    [
      "pairing bad ref",
      (d) => {
        d.requests[device.key].pairing = S("p:bad");
      },
      "INVALID_PRINCIPAL_REF",
    ],
    [
      "request key bad ref",
      (d) => {
        d.requests.bad = request();
        d.requests.bad.kind = U(0);
      },
      "INVALID_PRINCIPAL_REF",
    ],
    [
      "roster_bad_ref",
      (d) => {
        d.roster.bad = { profile: S("x"), endpoints: [], coordinator: S("") };
      },
      "INVALID_RESOURCE_REF",
    ],
    [
      "roster missing profile",
      (d) => {
        delete d.roster[resourceRef].profile;
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "roster missing endpoints",
      (d) => {
        delete d.roster[resourceRef].endpoints;
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "roster missing coordinator",
      (d) => {
        delete d.roster[resourceRef].coordinator;
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "roster endpoints scalar",
      (d) => {
        d.roster[resourceRef].endpoints = S("url");
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "roster endpoint bool",
      (d) => {
        d.roster[resourceRef].endpoints = [true];
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "roster Text",
      (d) => {
        d.roster[resourceRef].name = "text";
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "roster archived type",
      (d) => {
        d.roster[resourceRef].archived = U(0);
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "device missing label",
      (d) => {
        delete d.devices[device.key].label;
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "device missing kind",
      (d) => {
        delete d.devices[device.key].kind;
      },
      "MISSING_REQUIRED_FIELD",
    ],
    [
      "device key bad ref",
      (d) => {
        d.devices.bad = { label: S("bad") };
        d.devices.bad.kind = U(0);
      },
      "INVALID_PRINCIPAL_REF",
    ],
    [
      "device kind 2",
      (d) => {
        d.devices[device.key].kind = U(2);
      },
      "INVALID_ENUM_VALUE",
    ],
    [
      "device bad timestamp",
      (d) => {
        d.devices[device.key].added_at = S("2026-02-30T00:00:00Z");
      },
      "INVALID_TIMESTAMP",
    ],
    [
      "device revoked type",
      (d) => {
        d.devices[device.key].revoked = S("yes");
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "device missing_keys key",
      (d) => {
        d.devices[device.key].missing_keys = { bad: [] };
      },
      "INVALID_RESOURCE_REF",
    ],
    [
      "device missing_keys value",
      (d) => {
        d.devices[device.key].missing_keys = { [resourceRef]: S("bad") };
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "device missing_keys epoch",
      (d) => {
        d.devices[device.key].missing_keys = { [resourceRef]: [S("bad")] };
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "extension namespace",
      (d) => {
        d.extensions.bad = {};
      },
      "INVALID_EXTENSION_NAMESPACE",
    ],
  ];
  for (const [name, fn, code] of cases)
    it(name, () => {
      const v = check(fn);
      expect(v.usable).toBe(true);
      expect(v.problems.some((p) => p.diagnostic === code)).toBe(true);
      expect(v.problems.every((p) => p.code === "PROFILE_INVALID")).toBe(true);
    });

  for (const key of ["profile", "identity", "roster", "devices", "requests", "extensions"])
    it(`invalid root container ${key}`, () => {
      const v = check((d) => {
        delete d[key];
      });
      expect(v.usable).toBe(false);
      expect(v.problems[0]?.diagnostic).toBe("INVALID_ROOT");
      expect(v.roster).toEqual({});
      expect(v.devices).toEqual({});
      expect(v.requests).toEqual({});
    });

  it("identity_doc_bad_root / owner mismatch; per-value precedence", () => {
    const v = check((d) => {
      d.identity.root = S("p:bad");
    });
    expect(v.problems).toMatchObject([{ diagnostic: "INVALID_ROOT", pointer: "/identity/root" }]);
    expect(v.usable).toBe(false);
    const bad = check((d) => {
      d.requests[device.key].kind = U(2);
      d.requests[device.key].label = false;
    });
    expect(bad.problems.map((p) => p.diagnostic)).toEqual([
      "INVALID_FIELD_TYPE",
      "INVALID_ENUM_VALUE",
    ]);
  });

  it("per-entry validation leaves valid entries usable", () => {
    const v = check((d) => {
      delete d.requests[device.key].label;
      d.devices[device.key].revoked = true;
      d.roster[resourceRef].archived = true;
    });
    expect(v.requests).toEqual({});
    expect(v.devices[device.key]?.revoked).toBe(true);
    expect(v.roster[resourceRef]?.archived).toBe(true);
  });

  it("unknown and reserved data are preserved and ignored; no authority inferred", () => {
    const v = check((d) => {
      d.recovery = { future: true };
      d.succession = {};
      d.future = {};
      d.requests[device.key].extra = {};
      d.devices[device.key].mask = [1];
      d.extensions["org.example"] = { future: true };
    });
    expect(v.problems).toEqual([]);
    expect(v.devices[device.key]).not.toHaveProperty("mask");
    expect(v.requests[device.key]).not.toHaveProperty("extra");
  });

  it("timestamp grammar includes fractional seconds and leap second; endpoints may be empty", () => {
    const v = check((d) => {
      d.devices[device.key].added_at = S("2024-02-29T23:59:60.123Z");
      d.requests[device.key].requested_at = S("2026-11-04T01:00:00Z");
      d.roster[resourceRef].endpoints = [];
    });
    expect(v.problems).toEqual([]);
  });

  for (const [name, left, right, table] of [
    [
      "request_conflicted_kind",
      (d: Doc) => {
        d.requests[device.key].kind = U(1);
        d.requests[device.key].scope = [S(resourceRef)];
      },
      (d: Doc) => {
        delete d.requests[device.key].kind;
        d.requests[device.key].kind = U(0);
      },
      "requests",
    ],
    [
      "request_conflicted_valid_invalid",
      (d: Doc) => {
        d.requests[device.key].label = S("good");
      },
      (d: Doc) => {
        d.requests[device.key].label = false;
      },
      "requests",
    ],
    [
      "request conflicted valid labels",
      (d: Doc) => {
        d.requests[device.key].label = S("left");
      },
      (d: Doc) => {
        d.requests[device.key].label = S("right");
      },
      "requests",
    ],
    [
      "request_conflicted_maps",
      (d: Doc) => {
        d.requests[device.key] = request();
        d.requests[device.key].kind = U(0);
      },
      (d: Doc) => {
        d.requests[device.key] = request();
        d.requests[device.key].kind = U(0);
      },
      "requests",
    ],
    [
      "device conflicted kind",
      (d: Doc) => {
        d.devices[device.key].kind = U(1);
      },
      (d: Doc) => {
        delete d.devices[device.key].kind;
        d.devices[device.key].kind = U(0);
      },
      "devices",
    ],
    [
      "device conflicted valid invalid label",
      (d: Doc) => {
        d.devices[device.key].label = S("left");
      },
      (d: Doc) => {
        d.devices[device.key].label = false;
      },
      "devices",
    ],
  ] as const)
    it(name, () => {
      const start = base();
      const a = raw(start, left, personalWriter);
      const b = raw(start, right, otherWriter);
      const v = validateIdentity(A.merge(a, b), root);
      expect(v[table]).toEqual({});
      expect(v.problems.some((p) => p.diagnostic === "INVALID_FIELD_TYPE")).toBe(true);
    });

  it("roster_conflicted_name; devices may show any valid display value", () => {
    const start = base();
    const a = raw(
      start,
      (d) => {
        d.roster[resourceRef].name = S("left");
        d.devices[device.key].label = S("left");
      },
      personalWriter,
    );
    const b = raw(
      start,
      (d) => {
        d.roster[resourceRef].name = S("right");
        d.devices[device.key].label = S("right");
      },
      otherWriter,
    );
    const v = validateIdentity(A.merge(a, b), root);
    expect(v.problems).toEqual([]);
    expect(["left", "right"]).toContain(v.roster[resourceRef]?.name);
    expect(["left", "right"]).toContain(v.devices[device.key]?.label);
  });

  it("identical concurrent request scalar values are not conflicts (SOP §45)", () => {
    const start = base();
    const fn = (d: Doc) => {
      d.requests[device.key].label = S("same");
    };
    const v = validateIdentity(
      A.merge(raw(start, fn, personalWriter), raw(start, fn, otherWriter)),
      root,
    );
    expect(v.problems).toEqual([]);
    expect(v.requests[device.key]?.label).toBe("same");
  });

  it("device_entry_missing_keys_union: concurrent maps, lists, and scalar list elements", () => {
    const start = raw(
      base(),
      (d) => {
        d.devices[device.key].missing_keys = { [resourceRef]: [] };
        d.devices[device.key].missing_keys[resourceRef][0] = U(1);
      },
      rootWriter,
    );
    const a = raw(
      start,
      (d) => {
        d.devices[device.key].missing_keys[resourceRef][0] = U(2);
      },
      personalWriter,
    );
    const b = raw(
      start,
      (d) => {
        d.devices[device.key].missing_keys[resourceRef][0] = U(3);
      },
      otherWriter,
    );
    const merged = A.merge(a, b);
    expect(validateIdentity(merged, root).devices[device.key]?.missing_keys).toEqual({
      [resourceRef]: [2, 3],
    });
    const c = raw(
      start,
      (d) => {
        d.devices[device.key].missing_keys = { [resourceRef]: [] };
        d.devices[device.key].missing_keys[resourceRef][0] = U(5);
        d.devices[device.key].missing_keys[resourceRef][1] = U(1);
      },
      personalWriter,
    );
    const e = raw(
      start,
      (d) => {
        d.devices[device.key].missing_keys = { [resourceRef]: [] };
        d.devices[device.key].missing_keys[resourceRef][0] = U(8);
        d.devices[device.key].missing_keys[resourceRef][1] = U(5);
      },
      otherWriter,
    );
    const v = validateIdentity(A.merge(c, e), root);
    expect(v.problems).toEqual([]);
    expect(v.devices[device.key]?.missing_keys).toEqual({ [resourceRef]: [1, 5, 8] });
  });

  it("descriptor rejects noncanonical CBOR, bad ID, invalid Ed25519, trailing bytes and padding", () => {
    const badId = device.bytes.slice();
    badId[4] = (badId[4] as number) ^ 1;
    const badEd = device.bytes.slice();
    badEd.fill(0, 39, 71);
    for (const text of [
      toBase64url(Uint8Array.from([0xb8, 3, ...device.bytes.subarray(1)])),
      toBase64url(badId),
      toBase64url(badEd),
      toBase64url(Uint8Array.from([...device.bytes, 0])),
      `${device.text}=`,
    ])
      expect(
        check((d) => {
          d.requests[device.key].descriptor = S(text);
        }).problems[0]?.diagnostic,
      ).toBe("INVALID_DESCRIPTOR");
  });
});
