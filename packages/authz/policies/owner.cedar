// Owner has full access to resources they own.
// docs/01 §5: RBAC role vocabulary + ABAC conditions; deny by default, so
// access is granted only by an explicit permit that matches.
permit (
  principal,
  action,
  resource
)
when { resource has owner && resource.owner == principal };
