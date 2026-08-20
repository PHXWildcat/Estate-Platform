---
paths:
  - "apps/services/notifications/**"
  - "packages/notifications-client/**"
description: Notification content doctrine and delivery-outcome rules
---

# Notifications

**The doctrine is enforced BY CONSTRUCTION, not by review.**

- The wire schema carries a userId, a CLOSED namespaced kind enum, a channel and an
  optional deadline. **There is no field for text.** Do not add one — that is what stops
  any caller leaking estate content into a carrier message.
- ONE uniform subject for every kind: a mailbox observer learns that Estate wants
  attention, never which control fired. **No links, ever** — "we never link you" is only
  true if it is always true.
- The template registry is the only source of carrier-visible words.
- Each send route builds its schema from its OWN closed kind list, so a holder of one
  edge's credential structurally cannot fire another's. A kind that is not an estate
  notification (verification codes, account-security notices) is EXCLUDED from the shared
  list, or a send-credential holder can mail "enter this code: undefined".
- One credential per CAPABILITY, not per callee: send, recipient-upsert, verify, status
  and email-change are separate edges with separate holders. A service that only sends
  must not be able to repoint where anyone's alerts go.

## Delivery outcomes

- `SendOutcome` is a discriminated union. **`accepted` says the service replied;
  `delivered` says the mail went.** Narrowing on `accepted` and stopping type-checks
  perfectly while meaning something else — that put "delivered" in append-only audit
  events for notices nobody received.
- Use `wasDelivered()` from `@estate/notifications-client`. Only the three declared
  adapters may name the discriminant, and only as a negated gate.
- A recipient's verified bit is a property of the RECIPIENT; `deliversToRealChannels` is
  a property of the ADAPTER. They answer different questions — never substitute one.
- Notifications are a PRECONDITION for the controls that depend on them: routes whose
  waiting period nobody could be told about refuse in production rather than proceed.
