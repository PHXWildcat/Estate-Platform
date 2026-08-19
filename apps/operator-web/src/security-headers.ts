/**
 * THE OPERATOR ORIGIN'S CONTENT-SECURITY-POLICY (docs/03 §4 TB7).
 *
 * Identical in strength to the vault origin's, and deliberately so: the two
 * origins hold different things and the argument for the policy is the same
 * one. The vault holds Zone A key material; this one will hold the screen an
 * operator reads before approving a death case, locking an account, or granting
 * a stage of access to a dead person's estate. Both are surfaces where a
 * successful injection changes what a person is about to authorize.
 *
 * The main app ships an HONEST PARTIAL CSP: it allows inline script, because
 * Next's hydration bootstrap is inline, and says so plainly rather than writing
 * a stricter directive that gets relaxed under pressure (M11). Neither isolated
 * origin needs that compromise, for the same reason — there is no framework
 * here, so there is no framework bootstrap to exempt.
 *
 * WHAT IS ACTUALLY ENFORCED, and what each line is buying:
 *
 *   · `default-src 'none'` — everything is denied and each capability is then
 *     named. The main app starts from `'self'`; starting from nothing means a
 *     directive nobody thought about fails closed.
 *   · `script-src 'self'` — NO `'unsafe-inline'`, NO `'unsafe-eval'`, in EVERY
 *     environment including development. Nothing here needs React Refresh, so
 *     the M11 review's development-only carve-out has no counterpart.
 *   · `require-trusted-types-for 'script'` with `trusted-types 'none'` — NO
 *     POLICY MAY BE CREATED, so every DOM XSS sink (`innerHTML`, `outerHTML`,
 *     `insertAdjacentHTML`, `document.write`, `new Function`) throws rather than
 *     parsing. This is only enforceable because the client builds DOM with
 *     `createElement`/`textContent` and nothing else; a framework that templated
 *     through `innerHTML` would need a permissive policy, which is the control
 *     in name only.
 *   · `connect-src 'self'` — the client talks to this edge and to nowhere else.
 *     A successful injection here has no egress the browser will carry.
 *   · `img-src 'self'` — no `data:`, unlike the main app. Nothing on this origin
 *     needs it, and a `data:` image is a way to render attacker-chosen bytes.
 *   · `frame-ancestors 'none'` — nothing may frame this origin, so no other page
 *     can embed it and read timing or size signals from it.
 *   · `base-uri 'none'` — a `<base>` injection would otherwise repoint every
 *     relative script URL, defeating `script-src 'self'` without violating it.
 *
 * WHAT IT DELIBERATELY DOES NOT DO, stated here so nobody reads the strictness
 * above as completeness: a CSP is a browser-side control and cannot defend
 * against a compromised BUILD. The supply-chain half is the empty runtime
 * dependency tree and the absence of a bundler (`test/fences.spec.ts`), not this
 * header.
 *
 * There is no `'sha256-…'` and there is not meant to be: every script on this
 * origin is a file this edge serves, so the directive can stay `'self'` and
 * nothing else for the life of the app.
 */
export const OPERATOR_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "object-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
].join('; ');

/**
 * Headers every response from this origin carries.
 *
 * `Referrer-Policy: no-referrer` is stricter than the app's
 * `strict-origin-when-cross-origin`, and for a specific reason rather than
 * uniform paranoia: a URL on this origin will say which case an operator was
 * looking at, and a case id names somebody's death.
 *
 * `Cross-Origin-Opener-Policy: same-origin` severs the opener relationship, so
 * the page that launched the console holds no `window` handle to it.
 * `Cross-Origin-Resource-Policy: same-origin` stops any other origin from
 * loading resources from here at all.
 */
export const SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['Content-Security-Policy', OPERATOR_CSP],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'DENY'],
  ['Referrer-Policy', 'no-referrer'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['Cross-Origin-Resource-Policy', 'same-origin'],
  ['Cross-Origin-Embedder-Policy', 'require-corp'],
  ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'],
  // This origin is never cacheable: every response is either the shell or a
  // proxied answer about somebody's estate, and a shared cache holding either
  // is a disclosure. `no-store` rather than `no-cache` — the latter still
  // writes.
  ['Cache-Control', 'no-store'],
];
