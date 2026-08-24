// A RELEASED emergency-access grantee may READ the owner's vault items, and
// nothing else (docs/03 §5.2, docs/04 M27 PR3b). This is the first policy in
// the bundle that grants a principal access to a resource they do not own.
//
// TWO NARROWINGS, and both are load-bearing, because `loadBundledPolicies()`
// concatenates every `.cedar` in this directory into EVERY service's PDP — a
// policy written here is evaluated by profile, settlement and documents too:
//
//   1. `action == Action::"read_by_grantee"` — a dedicated ninth action id
//      rather than reusing `read`. The vault's own `read`, `read_history`,
//      `undelete` and `restore` stay owner-only, which is the entire reason
//      M27 PR1b split them into distinct ids instead of one `restore`.
//   2. `resource is VaultItem` — without it, any resource in any service that
//      happened to carry an `emergencyGrantees` attribute would match.
//
// The attribute is deliberately NOT named `namedBeneficiaries`:
// `beneficiary.cedar` permits plain `read` on anything carrying that name, so
// reusing it would hand every named beneficiary a Zone A vault read.
permit (
  principal,
  action == Action::"read_by_grantee",
  resource is VaultItem
)
when {
  resource has emergencyGrantees &&
  resource.emergencyGrantees.contains(principal)
};
