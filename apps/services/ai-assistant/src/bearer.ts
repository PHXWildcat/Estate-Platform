import type { CallerRequest } from '@estate/auth-guard';

/**
 * The caller's own bearer, re-extracted for forwarding to peer services.
 *
 * CallerGuard has already verified this token against identity; what it does not
 * do is hand it back, so the header is read again here. Forwarding it is how the
 * assistant reads assets, documents and profile WITHOUT holding a service
 * credential of its own (src/di-tokens.ts explains why that is the design): it
 * can reach exactly what this user could reach for themselves.
 *
 * A '' means a wiring anomaly and fails closed inside the clients, which refuse
 * to make a request at all on an empty bearer.
 *
 * It lives in its own module rather than in a controller because M10 PR3 added a
 * second controller that forwards (the analysis routes), and a copy-pasted
 * credential-extraction helper is the shape of drift this codebase has already
 * paid for twice — the seven byte-identical audit producers, and the
 * `describeIfPg` line copied into every e2e spec.
 */
export function bearerTokenOf(req: CallerRequest): string {
  const raw = req.headers['authorization'];
  const header = Array.isArray(raw) ? raw[0] : raw;
  return typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
}
