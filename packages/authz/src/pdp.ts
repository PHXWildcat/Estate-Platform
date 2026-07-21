import * as cedar from '@cedar-policy/cedar-wasm/nodejs';
import type { CedarValue, EntityInput, EntityRef } from './entities';

/**
 * Cedar Policy Decision Point. The platform's central authorization primitive
 * (docs/01 §5): **deny by default**. A request is permitted ONLY when Cedar
 * returns a definitive `allow`; every other outcome — an explicit deny, a
 * policy/schema error, a malformed request, or an unexpected exception from
 * the engine — resolves to `deny`. Authorization must never fail open.
 */

export type Decision = 'allow' | 'deny';

export interface AuthzRequest {
  principal: EntityRef;
  action: EntityRef;
  resource: EntityRef;
  /** Request context (e.g. settlement phase, MFA level, time). */
  context?: Record<string, CedarValue>;
  /** Entity attribute/hierarchy data the policies reference. */
  entities?: readonly EntityInput[];
}

export interface AuthzResult {
  decision: Decision;
  /** IDs of the policies that determined an allow (for audit — never PII). */
  determiningPolicies: string[];
  /**
   * Why a request was denied, for diagnostics. Enum-ish, never echoes request
   * data: 'not_permitted' (no matching permit) or 'engine_error' (policy/
   * schema/parse failure — also denied, and worth alerting on).
   */
  denyReason?: 'not_permitted' | 'engine_error';
}

export class PolicyDecisionPoint {
  /** @param policyText concatenated Cedar policy source (see loadPolicies). */
  constructor(private readonly policyText: string) {}

  authorize(request: AuthzRequest): AuthzResult {
    let answer: cedar.AuthorizationAnswer;
    try {
      answer = cedar.isAuthorized({
        principal: uid(request.principal),
        action: uid(request.action),
        resource: uid(request.resource),
        context: (request.context ?? {}) as cedar.Context,
        policies: { staticPolicies: this.policyText },
        entities: (request.entities ?? []).map(toEntityJson),
      });
    } catch {
      // The engine threw (e.g. a panic surfaced through wasm). Fail closed.
      return { decision: 'deny', determiningPolicies: [], denyReason: 'engine_error' };
    }

    if (answer.type !== 'success') {
      // Parse/validation failure ⇒ deny. This is a misconfiguration, not a
      // legitimate deny; upstream should alert on 'engine_error'.
      return { decision: 'deny', determiningPolicies: [], denyReason: 'engine_error' };
    }
    if (answer.response.decision === 'allow') {
      return {
        decision: 'allow',
        determiningPolicies: answer.response.diagnostics.reason,
      };
    }
    return {
      decision: 'deny',
      determiningPolicies: [],
      denyReason: 'not_permitted',
    };
  }
}

function uid(entity: EntityRef): cedar.EntityUid {
  return { type: entity.type, id: entity.id };
}

function toEntityJson(entity: EntityInput): cedar.EntityJson {
  return {
    uid: uid(entity.uid),
    attrs: (entity.attrs ?? {}) as cedar.EntityJson['attrs'],
    parents: (entity.parents ?? []).map(uid),
  };
}
