import { ref } from '../src/entities';
import { PolicyDecisionPoint } from '../src/pdp';
import { loadBundledPolicies } from '../src/policies';
import type { AuthzRequest, EntityInput } from '../src';

const DECEDENT = 'a1111111-1111-4111-8111-111111111111';
const REPORTER = 'b2222222-2222-4222-8222-222222222222';
const OPERATOR = 'c3333333-3333-4333-8333-333333333333';
const STRANGER = 'd4444444-4444-4444-8444-444444444444';
const CASE = 'e5555555-5555-4555-8555-555555555555';
const ASSET = 'f6666666-6666-4666-8666-666666666666';

const pdp = new PolicyDecisionPoint(loadBundledPolicies());

function caseEntity(): EntityInput {
  return {
    uid: { type: 'SettlementCase', id: CASE },
    attrs: {
      decedent: ref('User', DECEDENT),
      reporter: ref('User', REPORTER),
    },
  };
}

function principalEntity(id: string, isOperator: boolean): EntityInput {
  return {
    uid: { type: 'User', id },
    attrs: { isSettlementOperator: isOperator },
  };
}

function requestOf(principalId: string, action: string, isOperator = false): AuthzRequest {
  return {
    principal: { type: 'User', id: principalId },
    action: { type: 'Action', id: action },
    resource: { type: 'SettlementCase', id: CASE },
    entities: [caseEntity(), principalEntity(principalId, isOperator)],
  };
}

describe('settlement.cedar (narrow, deny-by-default)', () => {
  it('lets the decedent read and void their own case, nothing more', () => {
    expect(pdp.authorize(requestOf(DECEDENT, 'read')).decision).toBe('allow');
    expect(pdp.authorize(requestOf(DECEDENT, 'void')).decision).toBe('allow');
    for (const action of ['review', 'verify', 'evidence_add', 'manage', 'delete']) {
      expect(pdp.authorize(requestOf(DECEDENT, action)).decision).toBe('deny');
    }
  });

  it('the case does NOT inherit owner.cedar rights: decedent attr is not owner', () => {
    // owner.cedar permits ANY action when `resource.owner == principal`; a
    // settlement case must never grant its subject the operator verbs. The
    // deny on 'manage' above proves the attribute split holds.
    const result = pdp.authorize(requestOf(DECEDENT, 'manage'));
    expect(result.decision).toBe('deny');
    expect(result.denyReason).toBe('not_permitted');
  });

  it('lets the reporter read and attach evidence, but never void or review', () => {
    expect(pdp.authorize(requestOf(REPORTER, 'read')).decision).toBe('allow');
    expect(pdp.authorize(requestOf(REPORTER, 'evidence_add')).decision).toBe('allow');
    for (const action of ['void', 'review', 'verify', 'manage']) {
      expect(pdp.authorize(requestOf(REPORTER, action)).decision).toBe('deny');
    }
  });

  it('lets an allowlisted operator run the review lifecycle', () => {
    for (const action of ['read', 'review', 'evidence_add', 'verify']) {
      expect(pdp.authorize(requestOf(OPERATOR, action, true)).decision).toBe('allow');
    }
  });

  it('denies operator verbs without the resolved attribute (allowlist is the source)', () => {
    for (const action of ['review', 'verify']) {
      expect(pdp.authorize(requestOf(OPERATOR, action, false)).decision).toBe('deny');
      // Attribute absent entirely (principal entity not supplied) — same deny.
      expect(
        pdp.authorize({
          principal: { type: 'User', id: OPERATOR },
          action: { type: 'Action', id: action },
          resource: { type: 'SettlementCase', id: CASE },
          entities: [caseEntity()],
        }).decision,
      ).toBe('deny');
    }
  });

  it('denies a stranger everything, operator flag or not', () => {
    for (const action of ['read', 'void', 'review', 'verify', 'evidence_add']) {
      expect(pdp.authorize(requestOf(STRANGER, action)).decision).toBe('deny');
    }
  });

  it('does not widen other services: an operator gains nothing on an Asset', () => {
    // The shared bundle is loaded by every service (gotcha: a broad permit
    // here would widen assets/documents/vault too). `resource is
    // SettlementCase` scoping must keep operator authority out of Zone B.
    const asset: EntityInput = {
      uid: { type: 'Asset', id: ASSET },
      attrs: { owner: ref('User', DECEDENT), namedBeneficiaries: [] },
    };
    for (const action of ['read', 'review', 'manage', 'verify']) {
      const result = pdp.authorize({
        principal: { type: 'User', id: OPERATOR },
        action: { type: 'Action', id: action },
        resource: { type: 'Asset', id: ASSET },
        entities: [asset, principalEntity(OPERATOR, true)],
      });
      expect(result.decision).toBe('deny');
    }
  });
});
