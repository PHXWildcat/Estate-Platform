import { ref } from '../src/entities';
import { PolicyDecisionPoint } from '../src/pdp';
import { loadBundledPolicies } from '../src/policies';

const OWNER = 'a1111111-1111-4111-8111-111111111111';
const BENEFICIARY = 'b2222222-2222-4222-8222-222222222222';
const STRANGER = 'c3333333-3333-4333-8333-333333333333';
const ASSET = 'd4444444-4444-4444-8444-444444444444';

const pdp = new PolicyDecisionPoint(loadBundledPolicies());

/** Asset entity naming BENEFICIARY, owned by OWNER. */
function assetEntity() {
  return {
    uid: { type: 'Asset', id: ASSET },
    attrs: {
      owner: ref('User', OWNER),
      namedBeneficiaries: [ref('User', BENEFICIARY)],
    },
  };
}

function requestOf(principalId: string, action: 'read' | 'manage') {
  return {
    principal: { type: 'User', id: principalId },
    action: { type: 'Action', id: action },
    resource: { type: 'Asset', id: ASSET },
    entities: [assetEntity()],
  };
}

describe('PolicyDecisionPoint (deny-by-default)', () => {
  it('allows the owner to read and manage their asset', () => {
    expect(pdp.authorize(requestOf(OWNER, 'read')).decision).toBe('allow');
    expect(pdp.authorize(requestOf(OWNER, 'manage')).decision).toBe('allow');
  });

  it('allows a named beneficiary to READ the asset', () => {
    const result = pdp.authorize(requestOf(BENEFICIARY, 'read'));
    expect(result.decision).toBe('allow');
    expect(result.determiningPolicies.length).toBeGreaterThan(0);
  });

  it('denies a named beneficiary MANAGE (read-only grant)', () => {
    const result = pdp.authorize(requestOf(BENEFICIARY, 'manage'));
    expect(result.decision).toBe('deny');
    expect(result.denyReason).toBe('not_permitted');
  });

  it('denies a beneficiary who is not named on the asset', () => {
    const result = pdp.authorize(requestOf(STRANGER, 'read'));
    expect(result.decision).toBe('deny');
    expect(result.denyReason).toBe('not_permitted');
  });

  it('denies when the asset does not name any beneficiaries', () => {
    const result = pdp.authorize({
      principal: { type: 'User', id: BENEFICIARY },
      action: { type: 'Action', id: 'read' },
      resource: { type: 'Asset', id: ASSET },
      entities: [{ uid: { type: 'Asset', id: ASSET }, attrs: { owner: ref('User', OWNER) } }],
    });
    expect(result.decision).toBe('deny');
  });

  it('fails CLOSED to deny on malformed policy text (engine error)', () => {
    const broken = new PolicyDecisionPoint('this is not valid cedar @@@');
    const result = broken.authorize(requestOf(OWNER, 'read'));
    expect(result.decision).toBe('deny');
    expect(result.denyReason).toBe('engine_error');
  });

  it('denies with no entities supplied (nothing to match a permit)', () => {
    const result = pdp.authorize({
      principal: { type: 'User', id: OWNER },
      action: { type: 'Action', id: 'read' },
      resource: { type: 'Asset', id: ASSET },
    });
    expect(result.decision).toBe('deny');
  });
});
