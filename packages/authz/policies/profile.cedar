// Grant-based read for the core cluster (profiles, contacts, family members).
// A principal who holds an EFFECTIVE permission_grant — attached to a
// role_assignment whose scope covers this resource, within its time window —
// may READ that specific resource, and only that one. The Profile & Contacts
// PEP resolves effective grants from core.permission_grants / role_assignments
// and passes the resulting principal set as the resource's `grantees`
// attribute, so a role-holder can never enumerate resources their grant does
// not name (docs/01 §5, docs/03 §5.5 — the beneficiary-info-abuse boundary).
//
// Read-only: management (create/update/delete/manage) stays owner-only via
// owner.cedar. Deny by default — absent a matching grant, nothing here permits.
permit (
  principal,
  action == Action::"read",
  resource
)
when {
  resource has grantees && resource.grantees.contains(principal)
};
