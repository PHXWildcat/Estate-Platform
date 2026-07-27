import { z } from 'zod';

/**
 * Environment configuration for the Document service, zod-validated so the
 * process fails fast on a bad deployment instead of limping into runtime
 * errors. Mirrors the assets/plaid services' config posture.
 *
 * KMS_MASTER_KEY_HEX drives LocalKmsProvider and is a DEV/TEST convenience
 * only — production uses the AWS KMS adapter instead, enforced below. This
 * service's DEKs are wrapped under a DEDICATED KEK alias ('documents/kek'),
 * never another cluster's alias: the KMS grant is the isolation chokepoint
 * (docs/03 §5.3), so a compromise of another service can never unwrap a
 * document content DEK.
 *
 * OBJECT_STORE_MODE selects where encrypted content blobs live. 'fs' is the
 * dev/test local-filesystem store; 's3' is the real S3 store. Production
 * REQUIRES 's3' — a real deployment can never silently write to local disk.
 * Either way the store only ever receives ciphertext: envelope encryption
 * happens in this service before the write, so S3 SSE is defense in depth,
 * not the encryption boundary.
 */

const HEX_32_BYTES = /^[0-9a-fA-F]{64}$/;

const EnvSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3005),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    // Dev/test only: drives LocalKmsProvider. Required OUTSIDE production;
    // production uses AWS KMS instead (see AWS_KMS_KEY_ID).
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    // Production KMS: the KMS key id/alias/ARN that wraps THIS service's DEKs
    // (a different key than the other clusters'), plus its region.
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
    // Comma-separated broker list. Optional in dev/test; REQUIRED in
    // production — audit is a hard dependency of every sensitive action.
    KAFKA_BROKERS: z.string().optional(),
    // Base URL of the identity service, for cross-service session verification
    // (CallerGuard/StepUpGuard introspect the caller's token). Required IN
    // production; dev defaults to localhost.
    IDENTITY_URL: z.string().url().optional(),
    // Base URL of the settlement service (M7): the evidence-read route asks it
    // for authority before decrypting case evidence for an operator. Required
    // IN production; dev defaults to localhost. The client fails closed, so a
    // wrong value disables evidence reads rather than widening them.
    SETTLEMENT_URL: z.string().url().optional(),
    OBJECT_STORE_MODE: z.enum(['fs', 's3']).default('fs'),
    // fs mode: directory for the local object store (dev/test only).
    OBJECT_STORE_DIR: z.string().min(1).optional(),
    // s3 mode: the bucket holding encrypted content blobs.
    OBJECT_STORE_BUCKET: z.string().min(1).optional(),
    // Key for the per-user-keyed encrypted search index (document_search_tokens).
    // Required in every environment — search tokens are written on every
    // generation/upload.
    SEARCH_INDEX_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'SEARCH_INDEX_KEY_HEX must be 32 bytes of hex (64 chars)'),
    // Malware scanning on ingest (docs/01 §2.6). 'stub' is the deterministic
    // dev/test scanner (flags the EICAR test string); 'clamd' streams to a
    // ClamAV daemon over its INSTREAM protocol. Production REQUIRES 'clamd'.
    SCANNER_MODE: z.enum(['stub', 'clamd']).default('stub'),
    CLAMD_HOST: z.string().min(1).optional(),
    CLAMD_PORT: z.coerce.number().int().positive().max(65535).default(3310),
    // OCR for uploads. 'stub' is deterministic dev/test extraction; 'textract'
    // calls AWS Textract. Production REQUIRES 'textract'.
    OCR_MODE: z.enum(['stub', 'textract']).default('stub'),
  })
  .superRefine((env, ctx) => {
    if (env.NODE_ENV === 'production' && !env.KAFKA_BROKERS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KAFKA_BROKERS'],
        message: 'KAFKA_BROKERS is required in production (audit emission must not be a no-op)',
      });
    }
    if (env.NODE_ENV === 'production') {
      for (const key of ['AWS_KMS_KEY_ID', 'AWS_REGION'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required in production (LocalKmsProvider is dev/test only)`,
          });
        }
      }
      if (!env.IDENTITY_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['IDENTITY_URL'],
          message: 'IDENTITY_URL is required in production (cross-service session verification)',
        });
      }
      if (!env.SETTLEMENT_URL) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SETTLEMENT_URL'],
          message: 'SETTLEMENT_URL is required in production (evidence-read authority checks)',
        });
      }
      if (env.OBJECT_STORE_MODE !== 's3') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OBJECT_STORE_MODE'],
          message:
            'OBJECT_STORE_MODE must be "s3" in production (the filesystem store is dev/test only)',
        });
      }
      if (env.SCANNER_MODE !== 'clamd') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['SCANNER_MODE'],
          message: 'SCANNER_MODE must be "clamd" in production (the stub scanner is dev/test only)',
        });
      }
      if (env.OCR_MODE !== 'textract') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OCR_MODE'],
          message: 'OCR_MODE must be "textract" in production (the stub OCR is dev/test only)',
        });
      }
    } else if (!env.KMS_MASTER_KEY_HEX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KMS_MASTER_KEY_HEX'],
        message: 'KMS_MASTER_KEY_HEX is required outside production (drives LocalKmsProvider)',
      });
    }
    if (env.OBJECT_STORE_MODE === 's3') {
      for (const key of ['OBJECT_STORE_BUCKET', 'AWS_REGION'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when OBJECT_STORE_MODE is "s3"`,
          });
        }
      }
    }
    if (env.SCANNER_MODE === 'clamd' && !env.CLAMD_HOST) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CLAMD_HOST'],
        message: 'CLAMD_HOST is required when SCANNER_MODE is "clamd"',
      });
    }
    if (env.OCR_MODE === 'textract' && !env.AWS_REGION) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['AWS_REGION'],
        message: 'AWS_REGION is required when OCR_MODE is "textract"',
      });
    }
  });

/** Which KMS backs envelope encryption (local dev/test, AWS in production). */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | { readonly mode: 'aws'; readonly keyId: string; readonly region: string };

/** Which object store holds encrypted content blobs. */
export type ObjectStoreConfig =
  | { readonly mode: 'fs'; readonly dir: string }
  | { readonly mode: 's3'; readonly bucket: string; readonly region: string };

/** Which malware scanner gates upload ingest. */
export type ScannerConfig =
  | { readonly mode: 'stub' }
  | { readonly mode: 'clamd'; readonly host: string; readonly port: number };

/** Which OCR engine extracts text from uploads. */
export type OcrConfig =
  { readonly mode: 'stub' } | { readonly mode: 'textract'; readonly region: string };

export interface DocumentsConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly kms: KmsConfig;
  readonly kafkaBrokers: string[] | null;
  /** KEK alias wrapping THIS service's per-document DEKs. */
  readonly kekAlias: string;
  readonly objectStore: ObjectStoreConfig;
  /** HMAC key for the per-user-keyed encrypted search index. */
  readonly searchIndexKey: Buffer;
  readonly scanner: ScannerConfig;
  readonly ocr: OcrConfig;
  /** Identity service base URL for cross-service session verification. */
  readonly identityUrl: string;
  /** Settlement service base URL for evidence-read authority checks (M7). */
  readonly settlementUrl: string;
}

export class ConfigError extends Error {
  constructor(readonly issues: string[]) {
    // Issue paths and messages only — never env values.
    super(`invalid documents-service configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): DocumentsConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`),
    );
  }
  const e = parsed.data;
  const brokers = e.KAFKA_BROKERS
    ? e.KAFKA_BROKERS.split(',')
        .map((b) => b.trim())
        .filter((b) => b.length > 0)
    : [];
  if (e.NODE_ENV === 'production' && brokers.length === 0) {
    throw new ConfigError(['KAFKA_BROKERS: must list at least one broker in production']);
  }
  // The superRefine above guarantees the required fields per mode, so these
  // non-null assertions are sound.
  const kms: KmsConfig =
    e.NODE_ENV === 'production'
      ? { mode: 'aws', keyId: e.AWS_KMS_KEY_ID!, region: e.AWS_REGION! }
      : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') };
  const objectStore: ObjectStoreConfig =
    e.OBJECT_STORE_MODE === 's3'
      ? { mode: 's3', bucket: e.OBJECT_STORE_BUCKET!, region: e.AWS_REGION! }
      : { mode: 'fs', dir: e.OBJECT_STORE_DIR ?? '.object-store' };
  const scanner: ScannerConfig =
    e.SCANNER_MODE === 'clamd'
      ? { mode: 'clamd', host: e.CLAMD_HOST!, port: e.CLAMD_PORT }
      : { mode: 'stub' };
  const ocr: OcrConfig =
    e.OCR_MODE === 'textract' ? { mode: 'textract', region: e.AWS_REGION! } : { mode: 'stub' };
  return {
    nodeEnv: e.NODE_ENV,
    port: e.PORT,
    databaseUrl: e.DATABASE_URL,
    kms,
    kafkaBrokers: brokers.length > 0 ? brokers : null,
    kekAlias: 'documents/kek',
    objectStore,
    searchIndexKey: Buffer.from(e.SEARCH_INDEX_KEY_HEX, 'hex'),
    scanner,
    ocr,
    // superRefine requires IDENTITY_URL in production; dev falls back to local.
    identityUrl: e.IDENTITY_URL ?? 'http://localhost:3001',
    settlementUrl: e.SETTLEMENT_URL ?? 'http://localhost:3007',
  };
}
