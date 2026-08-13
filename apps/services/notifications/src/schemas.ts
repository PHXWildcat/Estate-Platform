import { BadRequestException } from '@nestjs/common';
import {
  ACCOUNT_SECURITY_KINDS,
  ESTATE_NOTIFICATION_KINDS,
  NOTIFICATION_CHANNELS,
  VERIFICATION_CODE_PATTERN,
} from '@estate/notifications-client';
import { z } from 'zod';

/** Payloads are ids, enums, a timestamp, and (on upsert) one address. */
export const BODY_LIMIT = '64kb';

/**
 * The send wire: content-free BY SCHEMA. `.strict()` means a caller that
 * tries to smuggle a subject, a body, or a template variable is refused with
 * invalid_request — the closed template registry is the only source of words.
 *
 * BUILT FROM `ESTATE_NOTIFICATION_KINDS`, NOT `NOTIFICATION_KINDS`, and that
 * subtraction is a control (M14). The wider constant is the vocabulary of the
 * send LOG; this narrower one is what a send-credential holder may fire.
 * `identity.address_verification` is excluded because its template needs a
 * code and this wire has nowhere to carry one — a holder naming it here would
 * otherwise mail somebody "enter this code: undefined", authored by a
 * credential vault, settlement and profile all hold. It travels on its own
 * route, behind its own credential, with its own typed input.
 */
export const SendSchema = z
  .object({
    userId: z.string().uuid(),
    kind: z.enum(ESTATE_NOTIFICATION_KINDS),
    channel: z.enum(NOTIFICATION_CHANNELS),
    deadline: z.string().datetime().optional(),
  })
  .strict();
export type SendInput = z.infer<typeof SendSchema>;

/**
 * The address-verification wire (M14). One id and one opaque platform-authored
 * code, `.strict()` like everything else so no subject, body or extra variable
 * can ride along.
 *
 * The code is bounded and character-restricted at the edge rather than trusted
 * from the caller: it is interpolated into a message body, and although the
 * only holder of this credential is identity — which mints it from
 * `randomBytes` over a fixed alphabet — a schema that accepted arbitrary text
 * here would be the free-text field the whole content doctrine exists to
 * refuse. The pattern admits identity's alphabet and its grouping separator
 * and nothing else, so this route cannot become one by drift.
 */
export const VerificationSchema = z
  .object({
    userId: z.string().uuid(),
    // The SHARED wire pattern, not a local copy — see its declaration in
    // @estate/notifications-client for why the M14 review moved it there. The
    // previous pattern here was `/^[0-9A-Z-]+$/` with `max(64)`, whose comment
    // claimed it "admits identity's alphabet and its grouping separator and
    // nothing else": false, and the gap was 64 characters of readable English
    // interpolated verbatim into a real message from the platform's verified
    // sender.
    code: z.string().regex(VERIFICATION_CODE_PATTERN, 'code must be a minted verification code'),
  })
  .strict();
export type VerificationInput = z.infer<typeof VerificationSchema>;

/**
 * The account-security wire (M17). One id and one kind from a CLOSED enum,
 * `.strict()`, and nothing else — no code, no text, no deadline, not even a
 * timestamp.
 *
 * BUILT FROM `ACCOUNT_SECURITY_KINDS`, which is a SUBSET of the system kinds,
 * for the same reason `SendSchema` is built from the estate ones. It admits
 * neither the estate kinds (that surface is held by vault, settlement and
 * profile) nor `identity.address_verification` (whose template needs a code
 * this wire cannot carry), so each of the three send routes can fire exactly
 * its own vocabulary and the exclusions are structural rather than a comment.
 *
 * NO DATE FIELD, deliberately, though "your password was changed at 14:02"
 * would read better. The moment this carries a variable, a holder chooses part
 * of what the user reads; the body says to sign in and check instead, which is
 * what a recipient should do anyway and cannot be dressed into a plausible lie.
 */
export const AccountSecuritySchema = z
  .object({
    userId: z.string().uuid(),
    kind: z.enum(ACCOUNT_SECURITY_KINDS),
  })
  .strict();
export type AccountSecurityInput = z.infer<typeof AccountSecuritySchema>;

/** RFC 5321 caps the path at 320 octets; anything longer is not an address. */
export const RecipientSchema = z
  .object({
    userId: z.string().uuid(),
    email: z.string().email().max(320),
  })
  .strict();
export type RecipientInput = z.infer<typeof RecipientSchema>;

/**
 * Validate a user id taken from the PATH. Path parameters reach a handler as
 * whatever the router matched, so the two routes keyed by `:userId` get the
 * same shape check the body-borne ids get — a malformed id must be a 400 here,
 * not a database error two layers down.
 */
export function parseUserId(userId: string): string {
  const parsed = z.string().uuid().safeParse(userId);
  if (!parsed.success) {
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data;
}

export function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    // Never echo the payload back: an upsert body carries an address.
    throw new BadRequestException({ error: 'invalid_request' });
  }
  return parsed.data;
}
