import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  BUNDLED_POLICY_DIR,
  loadBundledPolicies,
  PolicyDecisionPoint,
  ref,
  type AuthzRequest,
  type EntityInput,
} from '../src';

const OWNER = '11111111-1111-4111-8111-111111111111';
const GRANTEE = '22222222-2222-4222-8222-222222222222';
const STRANGER = '33333333-3333-4333-8333-333333333333';
const ITEM = '44444444-4444-4444-8444-444444444444';

const pdp = new PolicyDecisionPoint(loadBundledPolicies());

function vaultItem(grantees: readonly string[]): EntityInput {
  const attrs: Record<string, unknown> = { owner: ref('User', OWNER) };
  if (grantees.length > 0) {
    attrs['emergencyGrantees'] = grantees.map((id) => ref('User', id));
  }
  return { uid: { type: 'VaultItem', id: ITEM }, attrs } as EntityInput;
}

function requestOf(principalId: string, action: string, resource: EntityInput): AuthzRequest {
  return {
    principal: { type: 'User', id: principalId },
    action: { type: 'Action', id: action },
    resource: resource.uid,
    entities: [resource],
  };
}

describe('vault.cedar (the released grantee read, M27 PR3b)', () => {
  it('permits a named grantee to read_by_grantee', () => {
    expect(
      pdp.authorize(requestOf(GRANTEE, 'read_by_grantee', vaultItem([GRANTEE]))).decision,
    ).toBe('allow');
  });

  it('denies a principal the item does not name', () => {
    expect(
      pdp.authorize(requestOf(STRANGER, 'read_by_grantee', vaultItem([GRANTEE]))).decision,
    ).toBe('deny');
  });

  /**
   * THE ATTRIBUTE'S ABSENCE IS THE DENIAL, which is why
   * `vaultItemResource` omits it when the grantee set is empty rather than
   * passing `[]`. An owner-side call site that never learned about grantees
   * produces exactly this resource, and it must not be readable by anyone but
   * its owner.
   */
  it('denies read_by_grantee on an item that names NO grantees', () => {
    expect(pdp.authorize(requestOf(GRANTEE, 'read_by_grantee', vaultItem([]))).decision).toBe(
      'deny',
    );
  });

  /**
   * NARROWING (1): the action id. A grantee released to READ must not thereby
   * be able to update, delete or restore — the four ids exist separately for
   * this, and `owner.cedar` is the only policy that grants an unnamed action.
   */
  it('grants the grantee NOTHING but read_by_grantee', () => {
    for (const action of [
      'read',
      'read_history',
      'create',
      'update',
      'undelete',
      'restore',
      'delete',
      'manage',
    ]) {
      expect(pdp.authorize(requestOf(GRANTEE, action, vaultItem([GRANTEE]))).decision).toBe('deny');
    }
    // ANTI-VACUITY for the loop above: the SAME principal and resource DO get
    // an allow on the one action that is granted, so a policy file that failed
    // to load could not produce this pair.
    expect(
      pdp.authorize(requestOf(GRANTEE, 'read_by_grantee', vaultItem([GRANTEE]))).decision,
    ).toBe('allow');
  });

  /**
   * NARROWING (2): the resource type. `loadBundledPolicies()` concatenates
   * every `.cedar` into every service's PDP, so this policy is evaluated by
   * profile, settlement and documents too. Without `resource is VaultItem`, any
   * resource anywhere that happened to carry an `emergencyGrantees` attribute
   * would match it.
   */
  it('does not reach a NON-VaultItem resource carrying the same attribute', () => {
    const impostor: EntityInput = {
      uid: { type: 'Document', id: ITEM },
      attrs: { owner: ref('User', OWNER), emergencyGrantees: [ref('User', GRANTEE)] },
    };
    expect(pdp.authorize(requestOf(GRANTEE, 'read_by_grantee', impostor)).decision).toBe('deny');
  });

  /**
   * THE ATTRIBUTE NAME IS LOAD-BEARING. `beneficiary.cedar` permits plain
   * `read` on ANY resource whose `namedBeneficiaries` contains the principal,
   * so naming the grantee set that way would have handed every named
   * beneficiary a Zone A vault read — the one thing docs/03 §5.5 forbids.
   */
  it('does not let beneficiary.cedar reach a vault item', () => {
    const asBeneficiary: EntityInput = {
      uid: { type: 'VaultItem', id: ITEM },
      attrs: { owner: ref('User', OWNER), namedBeneficiaries: [ref('User', GRANTEE)] },
    };
    // The beneficiary policy DOES match `read` here — that is what it is for —
    // so the protection is that the vault never builds this shape, asserted in
    // `apps/services/vault/test/authz.spec.ts`. What must hold HERE is that
    // the two attributes are not interchangeable.
    expect(pdp.authorize(requestOf(GRANTEE, 'read_by_grantee', asBeneficiary)).decision).toBe(
      'deny',
    );
  });

  it('still lets the OWNER do everything, through owner.cedar', () => {
    for (const action of ['read', 'update', 'delete', 'manage', 'read_by_grantee']) {
      expect(pdp.authorize(requestOf(OWNER, action, vaultItem([GRANTEE]))).decision).toBe('allow');
    }
  });

  /**
   * THE BUNDLE IS THE CORPUS, stated and asserted. A fence whose input is
   * narrower than its claim goes green for the same reason it is wrong: if
   * `vault.cedar` were not in the directory the PDP loads, every `deny` above
   * would still pass.
   */
  it('reads vault.cedar from the bundle the PDP actually loads', () => {
    const files = readdirSync(BUNDLED_POLICY_DIR).filter((f) => f.endsWith('.cedar'));
    expect(files).toContain('vault.cedar');
    const text = readFileSync(join(BUNDLED_POLICY_DIR, 'vault.cedar'), 'utf8');
    expect(loadBundledPolicies()).toContain(text.trim());
    /*
     * COMMENTS STRIPPED FIRST, and the first draft of this test did not do it.
     * Deleting `resource is VaultItem` from the POLICY left this assertion
     * green, because the paragraph above the policy explains the narrowing by
     * name — the fence was reading the documentation of the rule instead of
     * the rule. Found by mutating it; it is the same defect as anchoring a
     * fence on an identifier a caller chose rather than on what the runtime
     * reads.
     */
    const policy = text.replace(/\/\/[^\n]*/g, '');
    expect(policy).toMatch(/action == Action::"read_by_grantee"/);
    expect(policy).toMatch(/resource is VaultItem/);
    // ANTI-VACUITY: stripping must not have emptied the corpus.
    expect(policy).toMatch(/permit\s*\(/);
  });
});
