import { createHash, timingSafeEqual } from 'node:crypto';
import {
  Inject,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';

/** DI token for the expected service credential (a config-injected secret). */
export const SERVICE_CREDENTIAL = Symbol('SERVICE_CREDENTIAL');

/** Header carrying the credential. Distinct from Authorization: this asserts a
 * calling SERVICE, never a user session, and must not be confusable with one. */
export const SERVICE_CREDENTIAL_HEADER = 'x-estate-service-credential';

interface ServiceCredentialRequest {
  headers: Record<string, string | string[] | undefined>;
}

/**
 * Service-to-service authentication for internal routes (M7). Some settlement
 * effects — locking a decedent's account, reading owner liveness — have no
 * user bearer token to forward by construction, and the target service cannot
 * know the caller's authorization state (identity does not know settlement's
 * operator allowlist). A dedicated static credential is the smallest honest
 * mechanism: the caller asserts "I am service X and I enforced my own checks",
 * and the target still enforces its own invariants on top. Interim until the
 * mesh (mTLS/SPIFFE, docs/01 §3) provides verifiable peer identity.
 *
 * ONE SECRET PER CALLEE, PER DIRECTION — not per pair of services, and never
 * one value reused for both what a service expects and what it presents. The
 * M7 security review found that reuse: settlement used a single config field
 * as both its inbound-expected and its outbound-presented value, which
 * transitively forced identity, settlement, vault and documents onto one
 * secret and handed the Zone A service a working key to identity's
 * irreversible account-lock API. Each credential is therefore named for the
 * CALLEE whose routes it opens (IDENTITY_INTERNAL_TOKEN,
 * DOCUMENTS_INTERNAL_TOKEN, SETTLEMENT_INTERNAL_TOKEN), and holding one grants
 * exactly that service's internal surface and nothing else.
 *
 * Fail-closed: an unwired (empty) expected credential refuses every request.
 */
@Injectable()
export class ServiceCredentialGuard implements CanActivate {
  constructor(@Inject(SERVICE_CREDENTIAL) private readonly expected: string) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<ServiceCredentialRequest>();
    const raw = request.headers[SERVICE_CREDENTIAL_HEADER];
    const presented = Array.isArray(raw) ? undefined : raw;
    if (!this.expected || typeof presented !== 'string' || presented.length === 0) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    // Compare fixed-length digests so the comparison is constant-time and
    // length-independent.
    const presentedDigest = createHash('sha256').update(presented).digest();
    const expectedDigest = createHash('sha256').update(this.expected).digest();
    if (!timingSafeEqual(presentedDigest, expectedDigest)) {
      throw new UnauthorizedException({ error: 'unauthorized' });
    }
    return true;
  }
}
