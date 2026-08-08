/**
 * THE VAULT ORIGIN'S CONTENT-SECURITY-POLICY (docs/03 §4 TB6, risk #4).
 *
 * The main app ships an HONEST PARTIAL CSP: it allows inline script, because
 * Next's hydration bootstrap is inline, and says so plainly rather than writing
 * a stricter directive that gets relaxed under pressure (M11). This origin does
 * not need that compromise, and the reason it does not is the whole shape of
 * this app: there is no framework here, so there is no framework bootstrap to
 * exempt.
 *
 * WHAT IS ACTUALLY ENFORCED, and what each line is buying:
 *
 *   · `default-src 'none'` — everything is denied and each capability is then
 *     named. The main app starts from `'self'`; starting from nothing means a
 *     directive nobody thought about fails closed.
 *   · `script-src 'self'` — NO `'unsafe-inline'`, NO `'unsafe-eval'`, in EVERY
 *     environment including development. Nothing here needs React Refresh, so
 *     the M11 review's development-only carve-out has no counterpart.
 *   · `require-trusted-types-for 'script'` with `trusted-types 'none'` — the
 *     one docs/03 TB6 asks for by name. `'none'` means NO POLICY MAY BE
 *     CREATED, so every DOM XSS sink (`innerHTML`, `outerHTML`,
 *     `insertAdjacentHTML`, `document.write`, `new Function`) throws rather
 *     than parsing. This is only enforceable because the client builds DOM with
 *     `createElement`/`textContent` and nothing else; a framework that
 *     templated through `innerHTML` would need a permissive policy, which is
 *     the control in name only.
 *   · `connect-src 'self'` — the client talks to this edge and to nowhere else.
 *     No provider, no CDN, no telemetry. A successful injection here has no
 *     egress that the browser will carry.
 *   · `img-src 'self'` — no `data:`, unlike the main app. The main app needs it
 *     for inline SVG and font fallbacks; nothing on this origin does, and a
 *     `data:` image is a way to render attacker-chosen bytes.
 *   · `frame-ancestors 'none'` — nothing may frame the vault, so the app origin
 *     cannot embed it and read timing or size signals from it.
 *   · `base-uri 'none'` — a `<base>` injection would otherwise repoint every
 *     relative script URL, defeating `script-src 'self'` without violating it.
 *
 * WHAT IT DELIBERATELY DOES NOT DO, stated here so nobody reads the strictness
 * above as completeness: a CSP is a browser-side control and cannot defend
 * against a compromised BUILD. The supply-chain half is the empty dependency
 * tree (`test/zero-dependency.spec.ts`) and the absence of a bundler, not this
 * header.
 *
 * There is no `'sha256-…'` and there is not meant to be. The client reaches
 * @estate/vault-crypto by ABSOLUTE PATH (`/lib/vault-crypto/index.js`, served
 * by this edge) rather than through an inline import map, precisely so that
 * this directive can stay `'self'` and nothing else for the life of the app.
 */
export const VAULT_CSP = [
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
 * uniform paranoia: the app origin's link INTO the vault would otherwise put
 * `vault.<domain>` in a Referer, and a URL on this origin says which vault
 * screen a user was on.
 *
 * `Cross-Origin-Opener-Policy: same-origin` severs the opener relationship, so
 * the page that launched the vault holds no `window` handle to it.
 * `Cross-Origin-Resource-Policy: same-origin` stops any other origin from
 * loading resources from here at all.
 */
export const SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['Content-Security-Policy', VAULT_CSP],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'DENY'],
  ['Referrer-Policy', 'no-referrer'],
  ['Cross-Origin-Opener-Policy', 'same-origin'],
  ['Cross-Origin-Resource-Policy', 'same-origin'],
  ['Cross-Origin-Embedder-Policy', 'require-corp'],
  ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'],
  // This origin is never cacheable: every response is either the shell or a
  // proxied answer about somebody's vault, and a shared cache holding either is
  // a disclosure. `no-store` rather than `no-cache` — the latter still writes.
  ['Cache-Control', 'no-store'],
];
