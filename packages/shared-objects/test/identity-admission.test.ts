import * as A from "@automerge/automerge";
import { describe, expect, it } from "vitest";
import { checkChange } from "../src/admission/index.js";
import { IdentityReplica } from "../src/identity/index.js";
import { principalRef } from "../src/values.js";
import {
  type Doc,
  device,
  edit,
  filled,
  initial,
  last,
  options,
  otherWriter,
  pairing,
  pairingWriter,
  personalWriter,
  request,
  resourceRef,
  rootWriter,
  S,
  secondDevice,
  unit,
} from "./support/identity.js";

describe("identity admission / ID-05 (§3 AI0–AI4)", () => {
  for (const container of ["roster", "devices", "requests", "extensions"]) {
    it(`AI0: ${container} must start empty; AI2: cannot replace or delete it`, () => {
      const bad = initial(rootWriter, (d) => {
        d[container].extra = {};
      });
      expect(IdentityReplica.fromChanges([unit(bad)], options).result.refused[0]?.diagnostic).toBe(
        "INVALID_ROOT",
      );
      const first = initial();
      for (const fn of [
        (d: Doc) => {
          d[container] = {};
        },
        (d: Doc) => {
          delete d[container];
        },
      ]) {
        const change = edit(first, fn);
        expect(
          IdentityReplica.fromChanges([unit(first), unit(change, personalWriter)], options).result
            .refused[0]?.diagnostic,
        ).toBe("CONTAINER_REPLACED");
      }
    });
  }

  it("AI2: an entry map created then overwritten in the same change", () => {
    const first = initial();
    const bad = edit(first, (d) => {
      d.roster[resourceRef] = {};
      d.roster[resourceRef] = true;
    });
    expect(
      IdentityReplica.fromChanges([unit(first), unit(bad, personalWriter)], options).result
        .refused[0]?.diagnostic,
    ).toBe("CONTAINER_REPLACED");
  });

  it("AI2: a scalar over a map held in an entry field, by the objects its operation replaces", () => {
    const base = filled();
    const withMap = edit(base.doc, (d) => {
      d.roster[resourceRef].future = { keep: true };
    });
    const bad = edit(
      withMap,
      (d) => {
        d.roster[resourceRef].future = S("scalar");
      },
      { ...personalWriter, actorSeq: 2 },
    );
    expect(
      IdentityReplica.fromChanges(
        [
          ...base.units,
          unit(withMap, personalWriter),
          unit(bad, { ...personalWriter, actorSeq: 2 }),
        ],
        options,
      ).result.refused[0]?.diagnostic,
    ).toBe("CONTAINER_REPLACED");
  });

  it("AI4: no deletion, map replacement, pairing conflict, or departure from own pairing", () => {
    const first = initial();
    const own = edit(
      first,
      (d) => {
        d.requests[device.key] = request();
      },
      pairingWriter,
    );
    for (const fn of [
      (d: Doc) => {
        delete d.requests[device.key];
      },
      (d: Doc) => {
        delete d.requests[device.key].label;
      },
      (d: Doc) => {
        d.requests[device.key] = request();
      },
      (d: Doc) => {
        d.requests[device.key].pairing = S(principalRef(personalWriter.signer));
      },
    ]) {
      const bad = edit(own, fn, pairingWriter);
      expect(
        IdentityReplica.fromChanges(
          [unit(first), unit(own, pairingWriter), unit(bad, { ...pairingWriter, actorSeq: 2 })],
          options,
        ).result.refused[0]?.diagnostic,
      ).toBe("UNAUTHORIZED_WRITER");
    }
    const changed = edit(
      own,
      (d) => {
        d.requests[device.key].pairing = S(principalRef(personalWriter.signer));
      },
      personalWriter,
    );
    const kept = edit(
      own,
      (d) => {
        delete d.requests[device.key].pairing;
        d.requests[device.key].pairing = S(principalRef(pairing));
      },
      rootWriter,
    );
    const conflicted = A.merge(A.clone(changed), A.clone(kept));
    const attempt = edit(
      conflicted,
      (d) => {
        d.requests[device.key].pairing = S(principalRef(pairing));
        d.requests[device.key].label = S("attempted conflict takeover");
      },
      pairingWriter,
    );
    const result = IdentityReplica.fromChanges(
      [
        unit(first),
        unit(own, pairingWriter),
        unit(changed, personalWriter),
        unit(kept, { ...rootWriter, actorSeq: 2 }),
        unit(attempt, { ...pairingWriter, actorSeq: 2 }),
      ],
      options,
    ).result;
    expect(result.refused[0]?.diagnostic).toBe("UNAUTHORIZED_WRITER");
  });

  it("root and personal writers may replace/delete entry maps; unknown keys survive", () => {
    const base = filled();
    const next = edit(base.doc, (d) => {
      d.roster[resourceRef] = { profile: S("replacement"), endpoints: [], coordinator: S("") };
      delete d.devices[device.key];
      d.future = { keep: true };
      d.recovery = {};
    });
    const { replica, result } = IdentityReplica.fromChanges(
      [...base.units, unit(next, personalWriter)],
      options,
    );
    expect(result.refused).toEqual([]);
    expect(replica.roster()[resourceRef]?.profile).toBe("replacement");
    expect(replica.devices()).toEqual({});
    expect(A.load<Doc>(replica.save()).future.keep).toBe(true);
  });
  it("identity_doc_initial", () => {
    const { replica, result } = IdentityReplica.fromChanges([unit(initial())], options);
    expect(result.refused).toEqual([]);
    expect(result.admitted).toHaveLength(1);
    expect(replica.validate()).toMatchObject({
      usable: true,
      problems: [],
      roster: {},
      devices: {},
      requests: {},
    });
  });

  for (const [name, writer, modify, expected] of [
    ["identity_doc_initial_by_device", personalWriter, undefined, "INVALID_ROOT"],
    [
      "identity_doc_initial_extra_key",
      rootWriter,
      (d: Doc) => {
        d.extra = S("extra");
      },
      "INVALID_ROOT",
    ],
    [
      "identity_doc_initial_filled_roster",
      rootWriter,
      (d: Doc) => {
        d.roster[resourceRef] = {};
      },
      "INVALID_ROOT",
    ],
    ["identity_doc_initial_in_unit_2", { ...rootWriter, actorSeq: 2 }, undefined, "INVALID_ROOT"],
    [
      "identity_doc_bad_root",
      rootWriter,
      (d: Doc) => {
        d.identity.root = S(principalRef(pairing));
      },
      "INVALID_ROOT",
    ],
  ] as const)
    it(name, () => {
      const { replica, result } = IdentityReplica.fromChanges(
        [unit(initial(writer, modify), writer)],
        options,
      );
      expect(result.refused[0]).toMatchObject({
        diagnostic: expected,
        code: "PROFILE_INVALID",
        held: false,
      });
      expect(replica.changes()).toEqual([]);
    });

  it("identity_doc_initial_seq_2", () => {
    const decoded = A.decodeChange(last(initial()));
    const bytes = A.encodeChange({ ...decoded, seq: 2 });
    expect(
      IdentityReplica.fromChanges([{ ...rootWriter, bytes }], options).result.refused[0]
        ?.diagnostic,
    ).toBe("INVALID_AUTOMERGE_BYTES");
  });

  it("actor binding and malformed-byte precedence", () => {
    expect(
      IdentityReplica.fromChanges([unit(initial(), personalWriter)], options).result.refused[0]
        ?.diagnostic,
    ).toBe("CHANGE_ACTOR_MISMATCH");
    expect(
      IdentityReplica.fromChanges([{ ...personalWriter, bytes: new Uint8Array([1]) }], options)
        .result.refused[0]?.diagnostic,
    ).toBe("INVALID_AUTOMERGE_BYTES");
  });

  const cases: [string, (d: Doc) => void, string][] = [
    [
      "identity_doc_profile_mutated",
      (d) => {
        d.profile = S("changed");
      },
      "IMMUTABLE_FIELD_MUTATED",
    ],
    [
      "identity.root mutation",
      (d) => {
        d.identity.root = S("changed");
      },
      "IMMUTABLE_FIELD_MUTATED",
    ],
    [
      "identity extension mutation",
      (d) => {
        d.identity.extra = {};
      },
      "IMMUTABLE_FIELD_MUTATED",
    ],
    [
      "identity deletion",
      (d) => {
        delete d.identity;
      },
      "IMMUTABLE_FIELD_MUTATED",
    ],
    [
      "identity_doc_container_replaced",
      (d) => {
        d.roster = {};
      },
      "CONTAINER_REPLACED",
    ],
    [
      "root container deleted",
      (d) => {
        delete d.requests;
      },
      "CONTAINER_REPLACED",
    ],
    [
      "entry map replaced with scalar",
      (d) => {
        d.roster[resourceRef] = false;
      },
      "CONTAINER_REPLACED",
    ],
    [
      "entry list replaced with scalar",
      (d) => {
        d.roster[resourceRef].endpoints = S("bad");
      },
      "CONTAINER_REPLACED",
    ],
    [
      "identity_doc_text_field",
      (d) => {
        d.devices[device.key].label = "Text";
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "Text in unknown root",
      (d) => {
        d.unknown = "Text";
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "Text in extensions",
      (d) => {
        d.extensions["example.org"] = { text: "Text" };
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "counter field",
      (d) => {
        d.devices[device.key].kind = new A.Counter(0);
      },
      "INVALID_FIELD_TYPE",
    ],
    [
      "nested map in scalar list",
      (d) => {
        d.roster[resourceRef].endpoints.push({ x: true });
      },
      "INVALID_FIELD_TYPE",
    ],
  ];
  for (const [name, modify, expected] of cases)
    it(name, () => {
      const { doc, units } = filled();
      const receiver = IdentityReplica.fromChanges(units, options).replica;
      const before = receiver.heads();
      const bad = edit(doc, modify);
      const dependent = edit(bad, (d) => {
        d.extra = true;
      });
      const result = receiver.receiveChanges([
        unit(bad, personalWriter),
        unit(dependent, { ...personalWriter, actorSeq: 2 }),
      ]);
      expect(result.refused[0]?.diagnostic).toBe(expected);
      expect(result.waiting).toEqual([checkChange(last(dependent)).hash]);
      expect(receiver.heads()).toEqual(before);
    });

  const unauthorized: [string, (d: Doc) => void][] = [
    [
      "pairing_writes_roster",
      (d) => {
        d.roster[resourceRef].name = S("attack");
      },
    ],
    [
      "pairing_deletes_roster",
      (d) => {
        delete d.roster[resourceRef];
      },
    ],
    [
      "pairing_writes_devices",
      (d) => {
        d.devices[device.key].label = S("attack");
      },
    ],
    [
      "pairing_writes_other_request",
      (d) => {
        d.requests[device.key].platform = S("attack");
      },
    ],
    [
      "pairing_wrong_pairing_field",
      (d) => {
        d.requests[secondDevice.key] = request(personalWriter.signer);
      },
    ],
    [
      "pairing_edits_foreign_request_label",
      (d) => {
        d.requests[device.key].label = S("attack");
      },
    ],
    [
      "pairing_takes_over_foreign_request",
      (d) => {
        d.requests[device.key].pairing = S(principalRef(pairing));
        d.requests[device.key].label = S("attack");
      },
    ],
    [
      "pairing_replaces_foreign_request_map",
      (d) => {
        d.requests[device.key] = request();
      },
    ],
    [
      "pairing writes two requests",
      (d) => {
        d.requests[secondDevice.key] = request();
        d.requests.other = request();
      },
    ],
    [
      "pairing writes extension",
      (d) => {
        d.extensions["example.org"] = {};
      },
    ],
  ];
  for (const [name, modify] of unauthorized)
    it(name, () => {
      const base = filled();
      const foreign = edit(
        base.doc,
        (d) => {
          d.requests[device.key] = request(otherWriter.signer);
        },
        otherWriter,
      );
      const receiver = IdentityReplica.fromChanges(
        [...base.units, unit(foreign, otherWriter)],
        options,
      ).replica;
      const bad = edit(foreign, modify, pairingWriter);
      expect(receiver.receiveChanges([unit(bad, pairingWriter)]).refused[0]?.diagnostic).toBe(
        "UNAUTHORIZED_WRITER",
      );
    });

  for (const writer of [pairingWriter, otherWriter])
    it(`pairing_writes_own_request / ${writer.writerClass}`, () => {
      const base = filled();
      const own = edit(
        base.doc,
        (d) => {
          d.requests[device.key] = request(writer.signer);
        },
        writer,
      );
      const { replica, result } = IdentityReplica.fromChanges(
        [...base.units, unit(own, writer)],
        options,
      );
      expect(result.refused).toEqual([]);
      expect(replica.validate().problems).toEqual([]);
      expect(replica.requests()[device.key]?.pairing).toBe(principalRef(writer.signer));
    });

  it("pairing_continues_own_request; pairing_class_at_control_ref", () => {
    const first = initial();
    const own = edit(
      first,
      (d) => {
        d.requests[device.key] = request();
      },
      pairingWriter,
    );
    const continued = edit(
      own,
      (d) => {
        d.requests[device.key].label = S("updated");
      },
      pairingWriter,
    );
    const { replica, result } = IdentityReplica.fromChanges(
      [unit(continued, { ...pairingWriter, actorSeq: 2 }), unit(own, pairingWriter), unit(first)],
      options,
    );
    expect(result.refused).toEqual([]);
    expect(replica.requests()[device.key]?.label).toBe("updated");
  });

  it("pairing_concurrent_same_key: causal admission, no winning map", () => {
    const first = initial();
    const a = edit(
      first,
      (d) => {
        d.requests[device.key] = request();
      },
      pairingWriter,
    );
    const b = edit(
      first,
      (d) => {
        d.requests[device.key] = request(otherWriter.signer);
      },
      otherWriter,
    );
    for (const branches of [
      [unit(a, pairingWriter), unit(b, otherWriter)],
      [unit(b, otherWriter), unit(a, pairingWriter)],
    ]) {
      const { replica, result } = IdentityReplica.fromChanges([unit(first), ...branches], options);
      expect(result.refused).toEqual([]);
      expect(replica.requests()).toEqual({});
      expect(replica.validate().problems[0]?.diagnostic).toBe("INVALID_FIELD_TYPE");
      // A continuation that only saw its own map still passes despite the receiver's conflict.
      const continuation = edit(
        a,
        (d) => {
          d.requests[device.key].label = S("offline");
        },
        pairingWriter,
      );
      expect(
        replica.receiveChanges([unit(continuation, { ...pairingWriter, actorSeq: 2 })]).refused,
      ).toEqual([]);
      // Seeing both maps is not unambiguous ownership.
      const seenBoth = A.merge(A.clone(a), A.clone(b));
      const attack = edit(
        seenBoth,
        (d) => {
          d.requests[device.key].label = S("takeover");
        },
        pairingWriter,
      );
      // Same actor sequence as continuation is held; test on a fresh replica instead.
      const fresh = IdentityReplica.fromChanges([unit(first), ...branches], options).replica;
      expect(
        fresh.receiveChanges([unit(attack, { ...pairingWriter, actorSeq: 2 })]).refused[0]
          ?.diagnostic,
      ).toBe("UNAUTHORIZED_WRITER");
    }
  });

  it("a root-created request with pairing=J is not J-owned", () => {
    const base = initial();
    const rootMade = edit(
      base,
      (d) => {
        d.requests[device.key] = request();
      },
      rootWriter,
    );
    const attempt = edit(
      rootMade,
      (d) => {
        d.requests[device.key].label = S("attack");
      },
      pairingWriter,
    );
    const out = IdentityReplica.fromChanges(
      [unit(base), unit(rootMade, { ...rootWriter, actorSeq: 2 }), unit(attempt, pairingWriter)],
      options,
    );
    expect(out.result.refused[0]?.diagnostic).toBe("UNAUTHORIZED_WRITER");
  });

  it("admission precedence: container, immutable, unauthorized, field type", () => {
    const base = initial();
    for (const [modify, expected] of [
      [
        (d: Doc) => {
          d.roster = {};
          d.profile = S("bad");
        },
        "CONTAINER_REPLACED",
      ],
      [
        (d: Doc) => {
          d.profile = S("bad");
          d.extra = "text";
        },
        "IMMUTABLE_FIELD_MUTATED",
      ],
      [
        (d: Doc) => {
          d.extra = "text";
        },
        "UNAUTHORIZED_WRITER",
      ],
    ] as const) {
      const bad = edit(base, modify, pairingWriter);
      expect(
        IdentityReplica.fromChanges([unit(base), unit(bad, pairingWriter)], options).result
          .refused[0]?.diagnostic,
      ).toBe(expected);
    }
  });
});
