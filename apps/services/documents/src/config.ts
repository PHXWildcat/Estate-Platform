import { z } from 'zod';

/**
 * Environment configuration for the Document service, zod-validated so the
 * process fails fast on a bad deployment instead of limping into runtime
 * errors. Mirrors the assets/plaid services' config posture.
 *
 * KMS_MODE selects the KMS backend. 'local' drives LocalKmsProvider from
 * KMS_MASTER_KEY_HEX and is a DEV/TEST convenience only; 'aws' is the real
 * KMS adapter. Production REQUIRES 'aws'. This service's DEKs are wrapped
 * under a DEDICATED KEK alias ('documents/kek'), never another cluster's
 * alias: the KMS grant is the isolation chokepoint (docs/03 §5.3), so a
 * compromise of another service can never unwrap a document content DEK.
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
    // Which KMS backs envelope encryption. 'local' is the in-process
    // LocalKmsProvider (dev/test only); 'aws' is the real KMS adapter.
    // Production REQUIRES 'aws' — see the superRefine below, which keeps the
    // production guarantee exactly as strong as when this was derived from
    // NODE_ENV. Making it an explicit enum, like OBJECT_STORE_MODE and
    // SCANNER_MODE already are, is what lets the AWS adapter be exercised
    // outside production (e.g. against a local KMS emulator) without ever
    // permitting the in-process key in a real deployment.
    KMS_MODE: z.enum(['local', 'aws']).default('local'),
    // Dev/test only: drives LocalKmsProvider. Required when KMS_MODE is
    // 'local'; unused under 'aws'.
    KMS_MASTER_KEY_HEX: z
      .string()
      .regex(HEX_32_BYTES, 'KMS_MASTER_KEY_HEX must be 32 bytes of hex (64 chars)')
      .optional(),
    // AWS KMS: the key id/alias/ARN that wraps THIS service's DEKs (a
    // different key than the other clusters'), plus its region.
    AWS_KMS_KEY_ID: z.string().min(1).optional(),
    AWS_REGION: z.string().min(1).optional(),
    // Endpoint override for the AWS SDK clients (KMS, S3, Textract). Unset
    // means the real AWS endpoints.
    //
    // The SDK already honours this variable ambiently, so we deliberately read
    // the SAME name rather than inventing one: when it is SET the value we pass
    // explicitly wins, so ours and the SDK's resolution cannot disagree.
    // Reading it here buys two things the ambient path does not — the
    // production TLS guard below, and `forcePathStyle` for S3, which has no
    // environment selector in the SDK at all and therefore requires this to be
    // an explicit decision.
    //
    // Precisely scoped, because an earlier phrasing here overclaimed "can never
    // disagree": when this is UNSET we pass no endpoint and the SDK resolves
    // ambiently, which includes the per-service overrides
    // (`AWS_ENDPOINT_URL_KMS`, `_S3`, `_TEXTRACT`) and `endpoint_url` in an AWS
    // config file. Those take precedence and the guard below never sees them.
    // The local stack's preflight refuses them outright; the production
    // residual is recorded in docs/05.
    AWS_ENDPOINT_URL: z.string().url().optional(),
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
    // Inbound credential for THIS service's internal legal-hold route (M7 PR2).
    // Named for the CALLEE: it opens documents' legal-hold API and nothing
    // else. The M7 security review found the earlier shared name collapsed
    // four services onto one secret; one secret per callee, per direction.
    // Unset ⇒ the guard fails closed and holds cannot be applied, which is
    // safe: enforcement already refuses deletion of anything already held.
    DOCUMENTS_INTERNAL_TOKEN: z.string().optional(),
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
    // calls AWS Textract; 'tesseract' calls a Tesseract sidecar over HTTP.
    // Production REQUIRES a NON-STUB engine — the guard names the stub rather
    // than naming one permitted engine, which is what its message has always
    // meant and what keeps it from rejecting future real adapters.
    OCR_MODE: z.enum(['stub', 'textract', 'tesseract']).default('stub'),
    // tesseract mode: base URL of the OCR sidecar.
    OCR_URL: z.string().url().optional(),
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
      if (env.KMS_MODE !== 'aws') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['KMS_MODE'],
          message: 'KMS_MODE must be "aws" in production (LocalKmsProvider is dev/test only)',
        });
      }
      // A plaintext endpoint would put wrapped DEKs and content ciphertext on
      // the wire in the clear. The SDK performs no such check on the variable.
      if (env.AWS_ENDPOINT_URL && !env.AWS_ENDPOINT_URL.startsWith('https://')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['AWS_ENDPOINT_URL'],
          message:
            'AWS_ENDPOINT_URL must be https in production (KMS/S3 traffic must not be plaintext)',
        });
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
      if (env.OCR_MODE === 'stub') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['OCR_MODE'],
          message: 'OCR_MODE must not be "stub" in production (the stub OCR is dev/test only)',
        });
      }
    }
    // Mode-conditional requirements, enforced in EVERY environment — the
    // OBJECT_STORE_MODE/SCANNER_MODE shape. Combined with the production pin
    // above, production still requires exactly AWS_KMS_KEY_ID + AWS_REGION and
    // still cannot reach LocalKmsProvider.
    if (env.KMS_MODE === 'aws') {
      for (const key of ['AWS_KMS_KEY_ID', 'AWS_REGION'] as const) {
        if (!env[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when KMS_MODE is "aws"`,
          });
        }
      }
    } else if (!env.KMS_MASTER_KEY_HEX) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['KMS_MASTER_KEY_HEX'],
        message:
          'KMS_MASTER_KEY_HEX is required when KMS_MODE is "local" (drives LocalKmsProvider)',
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
    if (env.OCR_MODE === 'tesseract' && !env.OCR_URL) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['OCR_URL'],
        message: 'OCR_URL is required when OCR_MODE is "tesseract"',
      });
    }
  });

/** Which KMS backs envelope encryption (local dev/test, AWS in production). */
export type KmsConfig =
  | { readonly mode: 'local'; readonly masterKey: Buffer }
  | {
      readonly mode: 'aws';
      readonly keyId: string;
      readonly region: string;
      /** Non-AWS KMS endpoint (a local emulator); null means real AWS. */
      readonly endpoint: string | null;
    };

/** Which object store holds encrypted content blobs. */
export type ObjectStoreConfig =
  | { readonly mode: 'fs'; readonly dir: string }
  | {
      readonly mode: 's3';
      readonly bucket: string;
      readonly region: string;
      /** Non-AWS S3 endpoint (an S3-compatible service); null means real AWS. */
      readonly endpoint: string | null;
    };

/** Which malware scanner gates upload ingest. */
export type ScannerConfig =
  | { readonly mode: 'stub' }
  | { readonly mode: 'clamd'; readonly host: string; readonly port: number };

/** Which OCR engine extracts text from uploads. */
export type OcrConfig =
  | { readonly mode: 'stub' }
  | {
      readonly mode: 'textract';
      readonly region: string;
      /** Non-AWS Textract endpoint; null means real AWS. */
      readonly endpoint: string | null;
    }
  | { readonly mode: 'tesseract'; readonly endpoint: string };

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
  /** Inbound credential for the internal legal-hold route ('' ⇒ refuse all). */
  readonly internalApiToken: string;
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
  const awsEndpoint = e.AWS_ENDPOINT_URL ?? null;
  const kms: KmsConfig =
    e.KMS_MODE === 'aws'
      ? { mode: 'aws', keyId: e.AWS_KMS_KEY_ID!, region: e.AWS_REGION!, endpoint: awsEndpoint }
      : { mode: 'local', masterKey: Buffer.from(e.KMS_MASTER_KEY_HEX!, 'hex') };
  const objectStore: ObjectStoreConfig =
    e.OBJECT_STORE_MODE === 's3'
      ? {
          mode: 's3',
          bucket: e.OBJECT_STORE_BUCKET!,
          region: e.AWS_REGION!,
          endpoint: awsEndpoint,
        }
      : { mode: 'fs', dir: e.OBJECT_STORE_DIR ?? '.object-store' };
  const scanner: ScannerConfig =
    e.SCANNER_MODE === 'clamd'
      ? { mode: 'clamd', host: e.CLAMD_HOST!, port: e.CLAMD_PORT }
      : { mode: 'stub' };
  // Exhaustive rather than a ternary chain ending in the stub. With three
  // engines a trailing `: { mode: 'stub' }` means any FUTURE engine silently
  // resolves to the stub — the same fail-open-in-style the M4 review found on
  // the scan gate. The `never` makes a new enum member a compile error here.
  const ocr: OcrConfig = ((): OcrConfig => {
    switch (e.OCR_MODE) {
      case 'textract':
        return { mode: 'textract', region: e.AWS_REGION!, endpoint: awsEndpoint };
      case 'tesseract':
        return { mode: 'tesseract', endpoint: e.OCR_URL! };
      case 'stub':
        return { mode: 'stub' };
      default: {
        const unreachable: never = e.OCR_MODE;
        throw new ConfigError([`OCR_MODE: unsupported engine ${String(unreachable)}`]);
      }
    }
  })();
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
    internalApiToken: e.DOCUMENTS_INTERNAL_TOKEN ?? '',
  };
}
