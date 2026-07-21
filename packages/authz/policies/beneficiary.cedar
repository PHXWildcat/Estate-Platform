// Beneficiaries may READ only the resources that explicitly name them, and
// only while their grant is effective (docs/01 §5, docs/03 §5.5 — a
// beneficiary must not enumerate assets that don't name them). This is a
// read-only permit; management stays owner-only via owner.cedar.
permit (
  principal,
  action == Action::"read",
  resource
)
when {
  resource has namedBeneficiaries &&
  resource.namedBeneficiaries.contains(principal)
};
