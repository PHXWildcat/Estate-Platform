// Settlement cases (M7, docs/03 §5.1 — the fraudulent-death-trigger flow).
//
// Every permit below is scoped with `resource is SettlementCase` so nothing
// here can widen decisions for the other services that load this shared
// bundle (assets, documents, vault, profile, identity). SettlementCase
// deliberately carries a `decedent` attribute, NOT `owner`: owner.cedar
// permits an owner ANY action on an owned resource, and the case subject must
// hold exactly two rights on their own death case — see it, and kill it.
// Operator authority comes from `isSettlementOperator`, resolved by the
// settlement PEP from the settlement_operators allowlist and passed as a
// principal attribute (the profile.cedar resolve-first pattern; policies never
// look anything up). Intake legitimacy (reporter is a linked contact of the
// decedent) is a documented row check in the service, not a Cedar decision —
// the vault requireGranteePolicy precedent.

// The case subject: read, and instantly void (docs/03 §5.1 control 3).
permit (
  principal,
  action in [Action::"read", Action::"void"],
  resource is SettlementCase
)
when { resource has decedent && resource.decedent == principal };

// The reporter: read the case they filed and attach further evidence.
permit (
  principal,
  action in [Action::"read", Action::"evidence_add"],
  resource is SettlementCase
)
when { resource has reporter && resource.reporter == principal };

// Allowlisted operators: read, the review lifecycle (start/approve/reject),
// evidence attach (operator-filed provider signals), and verify-confirm.
// Reviewer ≠ reporter and the liveness re-check are service-layer + DB
// invariants on top of this permit, not replaced by it.
permit (
  principal,
  action in [
    Action::"read",
    Action::"review",
    Action::"evidence_add",
    Action::"verify"
  ],
  resource is SettlementCase
)
when { principal has isSettlementOperator && principal.isSettlementOperator };
