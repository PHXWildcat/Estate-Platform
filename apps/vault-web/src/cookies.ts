import type { ServerResponse } from 'node:http';

/**
 * The vault origin's session cookie.
 *
 * `__Host-` IS THE CONTROL, not a naming convention. The prefix makes the
 * browser refuse the cookie unless it is `Secure`, has `Path=/`, and carries NO
 * `Domain` attribute — which means host-only, enforced by the browser rather
 * than by whoever writes the next `Set-Cookie`. That matters most in the
 * deployment this milestone assumes: `vault.<domain>` and `app.<domain>` share
 * a registrable domain, so a cookie set with `Domain=<domain>` anywhere would
 * be visible to both. With `__Host-` that is not a rule someone has to
 * remember.
 *
 * MEASURED before it was relied on: `vault.localhost` is a
 * potentially-trustworthy origin, so this cookie is accepted there over plain
 * http exactly as `localhost` accepts the BFF's. The same measurement showed
 * that the app origin's `estate_access`/`estate_refresh` are NOT sent here —
 * and that a port-only split would not have achieved that, because cookie scope
 * ignores the port.
 *
 * `SameSite=Lax`, NOT `Strict`, and this is the one place the vault is looser
 * than the app: the user ARRIVES by a cross-site top-level POST from the app
 * origin, and a `Strict` cookie would not be sent on the navigation that
 * follows the redirect — the user would land signed out on the origin they were
 * just handed to. Lax sends it on top-level navigations only, never on
 * cross-site subresource requests or form posts INTO this origin, so it costs
 * nothing that matters here: there is no state-changing GET on this edge, and
 * every mutating route requires the custom header below, which a cross-site
 * form cannot set.
 */
export const VAULT_SESSION_COOKIE = '__Host-estate_vault';

/**
 * CSRF defense, the BFF's second layer applied as the FIRST one here.
 *
 * The app's primary defense is `SameSite=Strict`; this origin cannot use that
 * (see above), so the custom header does the work: a cross-site attacker cannot
 * set it without a CORS preflight, and this edge answers no preflight for any
 * origin. Every mutating request from the client carries it. The one deliberate
 * exception is the handoff POST, which is a cross-site form submission by
 * design and is authorized by the code in its body instead.
 */
export const CSRF_HEADER = 'x-estate-vault-csrf';

/** Minimal cookie-header parser (first occurrence wins). No dependency. */
export function parseCookies(header: string | undefined): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  if (!header) {
    return cookies;
  }
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) {
      continue;
    }
    const name = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (name.length === 0 || cookies.has(name)) {
      continue;
    }
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      cookies.set(name, decodeURIComponent(value));
    } catch {
      cookies.set(name, value);
    }
  }
  return cookies;
}

/**
 * The attribute set, in one place, because a clear whose attributes differ from
 * the set silently fails to remove the cookie in some browsers — leaving a
 * "signed out" screen over a live session, which is the M8 PR5 logout lesson.
 */
function attributes(): string {
  return 'Path=/; HttpOnly; SameSite=Lax; Secure';
}

export function setSessionCookie(res: ServerResponse, token: string): void {
  res.appendHeader(
    'Set-Cookie',
    `${VAULT_SESSION_COOKIE}=${encodeURIComponent(token)}; ${attributes()}`,
  );
}

/** Expires it with the SAME attributes it was set with. */
export function clearSessionCookie(res: ServerResponse): void {
  res.appendHeader('Set-Cookie', `${VAULT_SESSION_COOKIE}=; ${attributes()}; Max-Age=0`);
}

export function sessionTokenFrom(cookieHeader: string | undefined): string | null {
  return parseCookies(cookieHeader).get(VAULT_SESSION_COOKIE) ?? null;
}
