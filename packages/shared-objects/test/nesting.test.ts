import * as A from "@automerge/automerge";
import { type ObjectId, principalId, resourceId, toHex } from "@openlfcp/core";
import { describe, expect, it } from "vitest";
import { createTask, deriveActorId, type LocalChange, SharedObjectsReplica } from "../src/index.js";

// SHARED-OBJECTS-PROFILE-01 §30 (SPEC-PATCH-07): an object's maps and lists
// nest at most 64 levels; the 65th is INVALID_FIELD_TYPE at its pointer and
// nothing below it is examined. Mirrors sdk-rs bb43a78. Synthetic values.

const RESOURCE = resourceId(Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16)));
const ALICE = principalId(Uint8Array.from({ length: 32 }, (_, i) => i));
const CAROL = principalId(Uint8Array.from({ length: 32 }, (_, i) => 128 + i));
const ID = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f" as ObjectId;
const opts = (principal = ALICE) => ({ resource: RESOURCE, principal });
const aliceActor = () => toHex(deriveActorId(RESOURCE, ALICE));

function alice() {
  const { replica, change: init } = SharedObjectsReplica.create(opts());
  const create = replica.apply(
    createTask({ id: ID, title: "Draft", createdBy: ALICE }).intent,
  ) as LocalChange;
  return { replica, init, create };
}

describe("nesting (§30)", () => {
  /** Alice's S01-like state with `levels` nested maps under extensions["org.example.app"]. */
  function nested(levels: number) {
    const a = alice();
    const doc = A.load(a.replica.save());
    const next = A.change(A.clone(doc, { actor: aliceActor() }), (d: Record<string, unknown>) => {
      let v: Record<string, unknown> = { leaf: 1 };
      for (let i = 1; i < levels; i++) v = { d: v };
      ((d.objects as Record<string, unknown>)[ID] as Record<string, unknown>).extensions = {
        "org.example.app": v,
      };
    });
    const carol = SharedObjectsReplica.fromChanges(A.getAllChanges(next), opts(CAROL)).replica;
    return carol;
  }

  it("accepts 64 levels and reports the 65th map at its own pointer, once", () => {
    expect(nested(63).validate().problems).toEqual([]);
    expect(
      nested(64)
        .validate()
        .problems.map((p) => [p.pointer, p.diagnostic]),
    ).toEqual([
      [`/objects/${ID}/extensions/org.example.app${"/d".repeat(63)}`, "INVALID_FIELD_TYPE"],
    ]);
  });
});
