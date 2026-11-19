// The control Resource C of a test world (E-015): a real
// ServiceControlReplica (admission by §3 and §4 included) behind the
// client's ServiceControlPort, with one replica shared by every writer as
// a coordinator would deliver it. Writers are given their class as the
// applier would derive it at control_ref; C's Control Chain is not modelled
// (the identity flows run on the MemoryCoordinator).

import type {
  ServiceControlCommitOutcome,
  ServiceControlCreator,
  ServiceControlPort,
} from "@openlfcp/client";
import { generateResourceId, type PrincipalId, type ResourceId } from "@openlfcp/core";
import {
  type ServiceControlIntent,
  ServiceControlReplica,
  type ServiceControlSignerClass,
} from "@openlfcp/shared-objects/service-control";

export type CommitFault = "crash-before-commit" | "crash-after-commit" | "queued" | undefined;

export class TestControl {
  readonly replica: ServiceControlReplica;
  /** Every change committed through a port, in order: `[who, operationId, intents]`. */
  readonly log: { readonly who: string; readonly operation: string; readonly intents: string[] }[] =
    [];
  /** A shared event log the test also appends identity uploads to, to check A3 before A4. */
  readonly events: string[] = [];
  synchronised = true;

  constructor(
    readonly root: PrincipalId,
    readonly resource: ResourceId = generateResourceId(),
  ) {
    this.replica = ServiceControlReplica.empty({
      resource: this.resource,
      root,
      genesisSigner: root,
    });
    this.write(root, "root", [{ intent: "initialize", attemptId: "attempt-1", createdAt: T0 }], 1);
  }

  /** A write by `signer` with class `cls` (unit sequence 2 unless given). */
  write(
    signer: PrincipalId,
    cls: ServiceControlSignerClass,
    intents: readonly ServiceControlIntent[],
    actorSeq = 2,
  ) {
    return this.replica.write({ signer, signerClass: cls, actorSeq }, intents);
  }

  /** The approving client's port: its writes are of class `cls`, each operation committed once. */
  port(
    who: PrincipalId,
    cls: ServiceControlSignerClass,
    fault: () => CommitFault = () => undefined,
  ): ServiceControlPort {
    const done = new Map<string, string>();
    return {
      resource: this.resource,
      state: () => (this.synchronised ? this.replica.validate() : undefined),
      creatorsOf: (container, key): readonly ServiceControlCreator[] =>
        this.replica.creatorsOf(container, key),
      commit: async (intents, operation): Promise<ServiceControlCommitOutcome> => {
        const f = fault();
        if (f === "crash-before-commit") throw new Error("crashed before the commit");
        const known = done.get(operation);
        if (known === undefined) {
          const list = intents as readonly ServiceControlIntent[];
          try {
            this.write(who, cls, list);
          } catch (e) {
            const diagnostic = (e as { diagnostic?: string }).diagnostic;
            if (diagnostic !== undefined) return { kind: "rejected", code: diagnostic };
            throw e;
          }
          done.set(operation, JSON.stringify(list));
          this.log.push({ who: cls, operation, intents: list.map((i) => i.intent) });
          this.events.push(`C:${list.map((i) => i.intent).join(",")}`);
        } else if (known !== JSON.stringify(intents)) throw new Error("operation ID reused");
        if (f === "crash-after-commit") throw new Error("crashed after the commit");
        return f === "queued" ? { kind: "queued" } : { kind: "acknowledged" };
      },
    };
  }
}

export const T0 = "2026-11-19T10:00:00Z";
