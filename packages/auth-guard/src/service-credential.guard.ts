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
 * operator allowlist). A dedicated static credential, provisioned to exactly
 * the two services that share it, is the smallest honest mechanism: the caller
 * asserts "I am the settlement service and I enforced my own checks", and the
 * target still enforces its own invariants on top. Interim until the mesh
 * (mTLS/SPIFFE, docs/01 §3) provides verifiable peer identity.
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
