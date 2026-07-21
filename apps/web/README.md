# @estate/web

Next.js (App Router) frontend for the Milestone 1 auth slice: register, login,
TOTP enrollment, step-up verification, and a step-up-gated demo export.

**Security posture:** auth lives in httpOnly cookies set by the BFF. This app
never sees, stores, or touches tokens — no auth material in localStorage,
sessionStorage, or JS-readable cookies, ever. The only thing persisted
client-side is the theme preference.

## Pages

| Route       | Purpose                                                                                                              |
| ----------- | -------------------------------------------------------------------------------------------------------------------- |
| `/`         | Landing. With a session: shows userId, MFA level, and a step-up freshness chip. Without: sign-in / create-account CTAs. |
| `/register` | Create account (email + password, client-side validation mirroring server rules).                                     |
| `/login`    | Sign in. Generic copy on `INVALID_CREDENTIALS` — never reveals whether an account exists.                             |
| `/security` | TOTP enrollment (otpauth URI as copyable text + verify), step-up form, and "Export data (demo)". A `STEPUP_REQUIRED` failure reveals the step-up form. |

## BFF contract

- `POST /graphql`, same-origin. `next.config.ts` rewrites `/graphql` →
  `${BFF_URL ?? 'http://localhost:4000'}/graphql` in dev.
- Every request: `content-type: application/json`, `x-estate-csrf: 1`,
  `credentials: 'include'`.
- Persisted operations: the body carries
  `extensions.persistedQuery.sha256Hash` (lowercase hex sha256 of the
  document) and, outside production only, the full `query`.
- Failures narrow to `extensions.code` ∈ `UNAUTHENTICATED`,
  `STEPUP_REQUIRED`, `INVALID_REQUEST`, `INVALID_CREDENTIALS` (plus
  client-local `NETWORK` / `UNKNOWN`). Server message text is never rendered;
  `src/lib/copy.ts` is the single code → copy map.

## GraphQL client layer

- `src/graphql/operations.ts` — every operation document, single source of truth.
- `src/graphql/client.ts` — `gqlRequest(op, variables)`: typed variables/data
  per operation, returns a discriminated `{ ok, data } | { ok, code }` result
  and never throws on server/network failure.
- `persisted-manifest.json` — checked-in map of hash → document.

### Regenerating the persisted manifest

After editing `operations.ts`:

```sh
node scripts/build-persisted-manifest.mjs
```

Commit the regenerated `persisted-manifest.json` together with the operation
change. `src/graphql/persisted-manifest.test.ts` re-derives every hash from
the TypeScript module and fails if the two drift.

## Theming and accessibility

- Design tokens are CSS custom properties in `src/app/globals.css`, exposed to
  Tailwind 4 via `@theme inline` (`bg-canvas`, `text-ink`, `border-line`,
  `text-danger`, …).
- Dark mode: `prefers-color-scheme` by default; the header toggle sets
  `data-theme` on `<html>` and persists to `localStorage` (`estate-theme`).
  An inline script in the root layout applies the stored choice before first
  paint. `color-scheme` is set per scheme so native controls match.
- Contrast: body text on canvas exceeds 7:1 in both schemes; all other
  text/background pairs meet WCAG AA at minimum.
- Forms: `<label htmlFor>` on every input, `aria-describedby` wiring for hints
  and errors, always-mounted `aria-live="polite"` error regions, visible
  `:focus-visible` rings, submit buttons disabled while in flight, and a
  skip-to-content link.

## Commands

```sh
pnpm --filter @estate/web dev        # dev server (expects BFF on :4000)
pnpm --filter @estate/web typecheck
pnpm --filter @estate/web test
pnpm --filter @estate/web build
```

`next-env.d.ts` is generated (and gitignored — it references `.next/types`,
which only exists after a build; `src/types/globals.d.ts` covers the CSS
module declaration a clean checkout needs).

## TODOs

- Replace the otpauth URI text with a locally rendered QR code (no third-party
  service — the URI is secret material).
- Logout, refresh-on-`UNAUTHENTICATED` retry, and session expiry UX
  (`refresh` mutation is already in the client layer).
- Passkey (WebAuthn) enrollment alongside TOTP.
- Persisted-query allowlist handshake with the BFF once it serves hashes from
  this manifest in production (drop the dev `query` field end-to-end).
- Motion (Framer) and the design-system component extraction into
  `packages/ui` once a second consumer exists.
