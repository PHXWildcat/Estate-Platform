import { timingSafeEqual } from 'node:crypto';
import {
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3ServiceException,
  type S3Client,
} from '@aws-sdk/client-s3';
import {
  assertValidKey,
  ObjectConflictError,
  ObjectNotFoundError,
  type ObjectStore,
} from './object-store';

/**
 * Production object store on S3. Receives CIPHERTEXT ONLY — envelope
 * encryption happens in the service before put(), so bucket-side SSE is
 * defense in depth, not the encryption boundary.
 *
 * Immutability: put() sends If-None-Match:* so S3 itself refuses to replace
 * an existing object; a 412 on a byte-identical body (idempotent republish)
 * is resolved by fetching and comparing. The client is injected so unit tests
 * exercise this logic against a stubbed transport (the kms-aws pattern).
 */
export class S3ObjectStore implements ObjectStore {
  constructor(
    private readonly client: Pick<S3Client, 'send'>,
    private readonly bucket: string,
  ) {}

  async put(key: string, body: Buffer): Promise<void> {
    assertValidKey(key);
    try {
      await this.client.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: key,
          Body: body,
          IfNoneMatch: '*',
        }),
      );
    } catch (err) {
      if (!isHttpStatus(err, 412)) {
        throw err;
      }
      const existing = await this.get(key);
      if (existing.length !== body.length || !timingSafeEqual(existing, body)) {
        throw new ObjectConflictError();
      }
      // Idempotent republish of identical bytes: success.
    }
  }

  async get(key: string): Promise<Buffer> {
    assertValidKey(key);
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: key }),
      );
      if (!response.Body) {
        throw new ObjectNotFoundError();
      }
      return Buffer.from(await response.Body.transformToByteArray());
    } catch (err) {
      if (isNotFound(err)) {
        throw new ObjectNotFoundError();
      }
      throw err;
    }
  }

  async exists(key: string): Promise<boolean> {
    assertValidKey(key);
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return true;
    } catch (err) {
      if (isNotFound(err)) {
        return false;
      }
      throw err;
    }
  }
}

function isNotFound(err: unknown): boolean {
  return (
    err instanceof S3ServiceException &&
    (err.name === 'NoSuchKey' || err.name === 'NotFound' || isHttpStatus(err, 404))
  );
}

function isHttpStatus(err: unknown, status: number): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    '$metadata' in err &&
    (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode === status
  );
}
