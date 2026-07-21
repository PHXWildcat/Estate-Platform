import type { ServerResponse } from 'node:http';

/**
 * Session cookie model: the web app NEVER sees tokens. The BFF stores the
 * identity service's opaque access/refresh tokens in httpOnly cookies and
 * forwards them server-side. SameSite=Strict is the primary CSRF defense
 * (see the x-estate-csrf check in app.ts for the belt-and-suspenders header).
 *
 * The cookies are session cookies (no Max-Age/Expires): token lifetime is
 * enforced server-side by the identity service, so an expired-on-the-server
 * cookie is harmless and the browser drops both on close.
 */
export const ACCESS_COOKIE = 'estate_access';
export const REFRESH_COOKIE = 'estate_refresh';

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

export function serializeSessionCookie(name: string, value: string, secure: boolean): string {
  const attributes = ['Path=/', 'HttpOnly', 'SameSite=Strict'];
  if (secure) {
    attributes.push('Secure');
  }
  return `${name}=${encodeURIComponent(value)}; ${attributes.join('; ')}`;
}

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
}

/** Appends both session cookies to the response. Values are never logged. */
export function setSessionCookies(
  res: ServerResponse,
  tokens: SessionTokens,
  secure: boolean,
): void {
  res.appendHeader('Set-Cookie', serializeSessionCookie(ACCESS_COOKIE, tokens.accessToken, secure));
  res.appendHeader(
    'Set-Cookie',
    serializeSessionCookie(REFRESH_COOKIE, tokens.refreshToken, secure),
  );
}
