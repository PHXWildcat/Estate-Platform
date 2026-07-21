# @estate/authz

The platform's central **Policy Decision Point** (docs/01 §5), built on Cedar
(`@cedar-policy/cedar-wasm`). **Deny by default**: a request is allowed only when
Cedar returns a definitive `allow`; explicit denies, policy/schema errors,
malformed requests, and engine exceptions all resolve to `deny`. Authorization
never fails open.

```ts
import { PolicyDecisionPoint, loadBundledPolicies, ref } from '@estate/authz';

const pdp = new PolicyDecisionPoint(loadBundledPolicies());

const result = pdp.authorize({
  principal: { type: 'User', id: userId },
  action: { type: 'Action', id: 'read' },
  resource: { type: 'Asset', id: assetId },
  entities: [
    {
      uid: { type: 'Asset', id: assetId },
      attrs: { owner: ref('User', ownerId), namedBeneficiaries: [ref('User', userId)] },
    },
  ],
});
// result.decision: 'allow' | 'deny'; result.determiningPolicies for audit;
// result.denyReason: 'not_permitted' | 'engine_error'
```

Services embed the PDP as their PEP and pass the entity attributes the policies
reference. `denyReason === 'engine_error'` means a misconfiguration (bad policy/
schema), not a legitimate deny — alert on it.

## Policies

Cedar source under `policies/*.cedar`, concatenated in sorted order, versioned
and reviewed like code. Shipped set (M2 starter):

- `owner.cedar` — an owner has full access to resources they own.
- `beneficiary.cedar` — a named beneficiary may **read** only resources whose
  `namedBeneficiaries` includes them (docs/03 §5.5: no asset enumeration);
  management stays owner-only.

## TODO

- A Cedar **schema** for request validation (`validateRequest: true`) once the
  entity/action vocabulary stabilizes.
- Time/state/settlement-phase conditions (effective-after-death grants, expiring
  guest access) as those domains land.
- Policy templates for per-resource grants (`permission_grants` linkage).
