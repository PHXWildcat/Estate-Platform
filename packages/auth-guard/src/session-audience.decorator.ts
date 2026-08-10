import { SetMetadata, type CustomDecorator } from '@nestjs/common';
import {
  DEFAULT_SESSION_AUDIENCE,
  SESSION_AUDIENCE_METADATA,
  type SessionAudience,
} from './session';

/**
 * Widen ONE route's admitted audiences (M15 PR3).
 *
 * `ALLOWED_SESSION_AUDIENCES` is the service-wide grant and is the right unit
 * when every route in a service belongs to the same trust zone — the vault
 * service. This is for the other case: a service that must stay `account`-only
 * while exposing a single route to another audience. Deny by default is
 * preserved, because an undecorated route falls back to the service-wide list,
 * which is `account` alone until a service says otherwise.
 *
 * `account` is always implied. A route that dropped it would be reachable from
 * the vault origin and nowhere else — a silent outage for ordinary callers
 * rather than a control.
 *
 * Which routes may carry this is declared in `AUDIENCE_ROUTE_ADMITTERS` and
 * checked against the real decorated handlers in both directions, so a route
 * that quietly acquires it fails the build.
 */
export function AllowSessionAudiences(
  ...audiences: readonly Exclude<SessionAudience, 'account'>[]
): CustomDecorator<string> {
  return SetMetadata<string, readonly SessionAudience[]>(SESSION_AUDIENCE_METADATA, [
    DEFAULT_SESSION_AUDIENCE,
    ...audiences,
  ]);
}
