import { Secret, TOTP } from 'otpauth';

const ISSUER = 'EstatePlatform';
const TOTP_PARAMS = { algorithm: 'SHA1', digits: 6, period: 30 } as const;

/** Fresh 160-bit TOTP secret (RFC 4226 recommended size). */
export function generateTotpSecretBase32(): string {
  return new Secret({ size: 20 }).base32;
}

/**
 * otpauth:// provisioning URI. The label is the opaque user id — deliberately
 * NOT the email address, so the URI (which clients may screenshot or sync to
 * authenticator clouds) carries no PII.
 */
export function totpProvisioningUri(secretBase32: string, userId: string): string {
  return new TOTP({
    issuer: ISSUER,
    label: userId,
    secret: Secret.fromBase32(secretBase32),
    ...TOTP_PARAMS,
  }).toString();
}

/** Validate a 6-digit code with a ±1 period window. */
export function verifyTotpCode(secretBase32: string, code: string): boolean {
  const totp = new TOTP({ secret: Secret.fromBase32(secretBase32), ...TOTP_PARAMS });
  return totp.validate({ token: code, window: 1 }) !== null;
}

/** Test helper: current code for a secret (used by the integration flow). */
export function currentTotpCode(secretBase32: string): string {
  return new TOTP({ secret: Secret.fromBase32(secretBase32), ...TOTP_PARAMS }).generate();
}
