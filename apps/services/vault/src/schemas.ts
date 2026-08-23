import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

/**
 * Request schemas. Field names never appear in the rejection - the wire format
 * is a single `invalid_request` token, because a validation message is a place
 * PII leaks from.
 */
export function parse<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new BadRequestException({ error: 'invalid_request' });
  return parsed.data as z.infer<T>;
}

export const UuidSchema = z.string().uuid();

/** docs/02 §5 vault_items.item_type. Plaintext metadata by design. */
export const VAULT_ITEM_TYPES = [
  'password',
  'pin',
  'recovery_codes',
  'seed_phrase',
  'private_key',
  'secure_note',
  'license',
  'attachment',
] as const;
export const VaultItemTypeSchema = z.enum(VAULT_ITEM_TYPES);
export type VaultItemType = z.infer<typeof VaultItemTypeSchema>;

/**
 * 68 KiB of blob, which leaves roughly 64 KiB of item content after the
 * envelope overhead. The server cannot inspect a blob, so size is the only
 * property it can bound - and an unbounded opaque blob is both a storage DoS
 * and a slow list endpoint. Large attachments need their own streaming path
 * and are a tracked follow-up rather than a silent allowance here (the M4
 * explicit-cap precedent).
 */
export const BLOB_MAX_BYTES = 69_632;
/** Transport ceiling above the schema-level one; base64 inflates by ~4/3. */
export const BODY_LIMIT = '128kb';

const Base64Blob = z
  .string()
  .min(1)
  .max(Math.ceil((BLOB_MAX_BYTES * 4) / 3) + 8)
  .refine((value) => /^[A-Za-z0-9+/]*={0,2}$/.test(value) && value.length % 4 === 0, {
    message: 'blob must be base64',
  })
  .refine((value) => Buffer.from(value, 'base64').byteLength <= BLOB_MAX_BYTES, {
    message: 'blob too large',
  })
  .refine((value) => Buffer.from(value, 'base64').byteLength > 0, {
    message: 'blob must not be empty',
  });

/** base64 of a fixed-width value (SRP group elements, salts, proofs). */
function base64OfBytes(byteLength: number): z.ZodEffects<z.ZodString, string, string> {
  return z
    .string()
    .refine(
      (value) =>
        /^[A-Za-z0-9+/]*={0,2}$/.test(value) &&
        value.length % 4 === 0 &&
        Buffer.from(value, 'base64').byteLength === byteLength,
      { message: 'invalid encoded value' },
    );
}

export const SRP_ELEMENT_BASE64 = base64OfBytes(512);
export const SALT_BASE64 = base64OfBytes(16);
export const PROOF_BASE64 = base64OfBytes(32);

/**
 * KDF parameters, validated on the way IN as well as pinned on the client. The
 * server has no way to use these, but it should not store a profile it does not
 * recognise: a keyset with unsupported parameters is a vault nobody can open.
 */
export const KdfParamsSchema = z
  .object({
    v: z.literal(1),
    alg: z.literal('pbkdf2-sha256'),
    iterations: z.number().int().min(600_000).max(10_000_000),
    aukSalt: SALT_BASE64,
    srpGroup: z.literal('rfc5054-4096'),
    cipher: z.literal('aes-256-gcm'),
  })
  .strict();

export const KeysetPayloadSchema = z
  .object({
    srpSalt: SALT_BASE64,
    srpVerifier: SRP_ELEMENT_BASE64,
    wrappedMasterKey: z.string().min(1).max(1024),
    kdfParams: KdfParamsSchema,
  })
  .strict();

export const CreateKeysetSchema = KeysetPayloadSchema;

export const ReplaceKeysetSchema = KeysetPayloadSchema.extend({
  /** HMAC over the payload under the SRP-derived keyset-auth key. */
  proof: PROOF_BASE64,
}).strict();

export const SrpVerifySchema = z
  .object({
    handshakeId: UuidSchema,
    clientPublic: SRP_ELEMENT_BASE64,
    clientProof: PROOF_BASE64,
  })
  .strict();

export const CreateItemSchema = z
  .object({
    /** Client-generated: the id is bound into the blob's AAD. */
    id: UuidSchema,
    itemType: VaultItemTypeSchema,
    blob: Base64Blob,
  })
  .strict();

export const UpdateItemSchema = z
  .object({
    itemType: VaultItemTypeSchema,
    blob: Base64Blob,
  })
  .strict();

export const ListItemsQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(500).default(100),
    cursor: z.string().min(1).max(200).optional(),
  })
  .strict();

/**
 * M27 PR1b's readers (docs/03 §6ww).
 *
 * The versions cursor is a plain `revision`, not the shadow table's
 * `version_seq`: per-item, never reused, and already the client's `If-Match`
 * token. `version_seq` is a platform-wide BIGINT identity and putting it on
 * the wire would be a sequential id and a write-volume oracle at once.
 */
export const ListVersionsQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(50),
    cursor: z.coerce.number().int().min(1).max(1_000_000_000).optional(),
  })
  .strict();

export const ListRestorableQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(500).default(100),
    cursor: z.string().min(1).max(200).optional(),
  })
  .strict();

/**
 * Which image to put back. `revision` NAMES it; `If-Match` (a header, not this
 * body) says which live revision the caller believed it was replacing. Two
 * numbers with two jobs, and conflating them is what M27 PR1a split apart.
 */
export const RestoreVersionSchema = z
  .object({ revision: z.coerce.number().int().min(1).max(1_000_000_000) })
  .strict();

/** `If-Match: <revision>` - the assets optimistic-concurrency precedent. */
export const IfMatchSchema = z.coerce.number().int().min(1).max(1_000_000_000);

// --- emergency access (docs/03 §5.2) ---

/** Raw uncompressed P-256 point. */
export const PUBLIC_KEY_BASE64 = base64OfBytes(65);
export const SHA256_BASE64 = base64OfBytes(32);

export const PublishRecoveryKeySchema = z
  .object({
    publicKey: PUBLIC_KEY_BASE64,
    wrappedPrivateKey: z.string().min(1).max(2048),
  })
  .strict();

/**
 * docs/02 §5 puts the >=24h floor in the DDL; it is restated here so a bad
 * value is a 400 at the edge rather than a constraint violation deeper in.
 * There is no ceiling: an owner who wants to make their contacts wait a month
 * is expressing a preference, not a misconfiguration.
 */
export const WAITING_PERIOD_HOURS = z.number().int().min(24).max(8760);

export const GranteeSchema = z
  .object({
    granteeContactId: UuidSchema,
    granteeUserId: UuidSchema,
    /** The Shamir share, sealed to the grantee's public key. */
    keyShare: z.string().min(1).max(4096),
    granteePublicKeySha256: SHA256_BASE64,
    waitingPeriodHours: WAITING_PERIOD_HOURS,
  })
  .strict();

export const ConfigureEmergencyAccessSchema = z
  .object({
    threshold: z.number().int().min(1).max(255),
    platformPart: base64OfBytes(32),
    wrappedMasterKeyRecovery: z.string().min(1).max(1024),
    grantees: z.array(GranteeSchema).min(1).max(64),
  })
  .strict();
