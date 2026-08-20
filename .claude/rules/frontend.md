---
paths:
  - "apps/web/**"
  - "apps/operator-web/**"
  - "apps/bff/**"
description: Web, BFF and GraphQL surface rules
---

# Frontend and BFF

- **The BFF holds no credential.** It forwards the caller's own bearer downstream and
  injects no identity header, so a compromised BFF replays the sessions it is currently
  serving and cannot mint new authority. Keep it that way.
- **A missing field is NO DATA, never data.** `{"data":{}}` from a version-skewed peer
  must not destructure — that has white-screened a page in four separate milestones.
  Guard the shape at every loader.
- **A failed read is not an empty one.** Never render a refused list as "nothing here";
  a short worklist and a 503 are different facts. Refusals cost their own panel.
- Money is a decimal STRING end to end; never parse it to a float. Percentages are
  formatted at the wire's own precision — `100 - x` on floats prints
  `97.94200000000001%`. Any COMPUTED number goes through a formatter.
- Adding an operation means REGENERATING the persisted-query manifest. A document added
  to `operations.ts` without it is green in dev, tests and CI, and dead in production
  with "Operation not allowed".
- Enum mirrors are DERIVED from the BFF's SDL (`graphql/enum-parity.test.ts`). GraphQL
  serialises an enum as its member NAME — an app-side union of lowercase strings makes
  every comparison permanently false and type-checks perfectly.
- Error-code unions must match the BFF's exactly, both directions
  (`error-codes.test.ts`). An unrecognised code renders a control firing as an outage.
- **Model output renders as PLAIN TEXT.** No markdown parser, no
  `dangerouslySetInnerHTML` anywhere in the app (one declared exemption: the theme
  script in `layout.tsx`). Stored document HTML is framed in a `sandbox=""` iframe —
  `DocumentViewer.tsx` is the ONLY file allowed to render an `<iframe>`.
- **Audited-decrypt volume is a UI constraint.** Every content/PII read emits an audit
  event and spends a KMS operation. No content field on list types, no prefetch, no
  cache that makes a repeat read invisible.
- Step-up prompts: exactly ONE open at a time; the retried action is a discriminated
  union CARRYING its own arguments (never re-read from current form state); the prompt
  REPLACES the form it guards (never nests inside it — a nested `<form>` makes
  `querySelectorAll('form')` ambiguous); Cancel aborts the polling loop AND every other
  exit path from the screen. Peers learn of an elevation through a ~30s positive
  introspection cache, so the retry must poll to a deadline, not fire once.
- Two form fields must never share a label. Name what the field IS, not which one.
- Never offer an action the server would refuse.
