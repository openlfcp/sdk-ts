// Type-level checks, compiled by `pnpm typecheck` (not run by vitest).
import {
  type ControlRecordId,
  controlRecordId,
  dataUnitId,
  type ObjectId,
  parseObjectId,
  type ResourceId,
  resourceId,
} from "../src/index.js";

function wantsControlRecordId(id: ControlRecordId): ControlRecordId {
  return id;
}
function wantsResourceId(id: ResourceId): ResourceId {
  return id;
}

const unit = dataUnitId(new Uint8Array(32));
wantsControlRecordId(controlRecordId(new Uint8Array(32)));

// @ts-expect-error a DataUnitId is not accepted where a ControlRecordId is expected
wantsControlRecordId(unit);

// @ts-expect-error a ControlRecordId is not a ResourceId
wantsResourceId(controlRecordId(new Uint8Array(32)));

// @ts-expect-error an unvalidated Uint8Array is not an identifier
wantsResourceId(new Uint8Array(32));

wantsResourceId(resourceId(new Uint8Array(32)));

// @ts-expect-error a plain string is not an ObjectId without parsing
export const unparsed: ObjectId = "019a2f85-7b31-7c42-b85a-fc843e2f40ad";
export const parsed: ObjectId = parseObjectId("019a2f85-7b31-7c42-b85a-fc843e2f40ad");
