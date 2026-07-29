import { randomBytes, randomUUID } from 'node:crypto';
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { PutObjectCommand, S3Client, S3ServiceException } from '@aws-sdk/client-s3';
import { S3ObjectStore, s3ClientConfig } from '@estate/service-documents/dist/s3-object-store';
import { ObjectNotFoundError } from '@estate/service-documents/dist/object-store';

/**
 * CONFORMANCE PROBES: does the AWS implementation this stack runs against
 * behave the way our adapters ASSUME it does?
 *
 * Three behaviours are load-bearing and none of them is proven by a unit test
 * against a mocked transport:
 *
 *  1. KMS `Decrypt` must ENFORCE the EncryptionContext. `AwsKmsProvider` binds
 *     every DEK to `estate:kek = <alias>` — the AWS-side analogue of the AAD
 *     binding, and with LocalStack's missing IAM it is the ONLY cross-domain
 *     control the stack exercises. If the emulator ignored it, six per-service
 *     keys would be pure theatre and docs/05's limits section must say so.
 *  2. S3 `PutObject` with `IfNoneMatch: '*'` must fail on an existing key.
 *     Object immutability rests on it. This can rot in TWO directions: an
 *     emulator that ignores the header silently loses immutability with every
 *     test green; one that rejects it with the wrong shape breaks every put.
 *  3. S3 not-found must surface as an `S3ServiceException` — the store's 404
 *     mapping is gated on `instanceof`, so a divergent error type rethrows
 *     instead of becoming `ObjectNotFoundError`.
 *
 * WRITTEN TO RUN AGAINST REAL AWS TOO. Everything is parameterized:
 * `CONFORMANCE_*` env vars override the LocalStack defaults, so the same file
 * run with real credentials, a real key ARN and a real bucket upgrades
 * docs/05 from "LocalStack does X" to "AWS and LocalStack agree on X".
 * Nothing here reads `.env.stack`, and the endpoint default is the published
 * LocalStack port — the doctor's guards keep real credentials out of stack
 * files, not out of a deliberate, explicitly-configured probe run.
 */
const describeIfStack = process.env['STACK_TEST'] ? describe : describe.skip;

const ENDPOINT = process.env['CONFORMANCE_AWS_ENDPOINT'] ?? 'http://localhost:4566';
const REGION = process.env['CONFORMANCE_AWS_REGION'] ?? 'us-east-1';
const KEY_ID = process.env['CONFORMANCE_KMS_KEY_ID'] ?? 'alias/estate-documents-kek';
const BUCKET = process.env['CONFORMANCE_S3_BUCKET'] ?? 'estate-documents-local';
/** Real AWS resolves credentials ambiently; LocalStack takes the dummies. */
const CREDS = process.env['CONFORMANCE_AMBIENT_CREDENTIALS']
  ? {}
  : { credentials: { accessKeyId: 'test', secretAccessKey: 'test' } };

jest.setTimeout(60_000);

describeIfStack('AWS conformance: the behaviours the adapters assume', () => {
  const kms = new KMSClient({ region: REGION, endpoint: ENDPOINT, ...CREDS });
  const s3 = new S3Client({ ...s3ClientConfig(REGION, ENDPOINT), ...CREDS });

  it('KMS Decrypt enforces the EncryptionContext (the cross-domain binding)', async () => {
    const context = { 'estate:kek': 'documents/kek' };
    const generated = await kms.send(
      new GenerateDataKeyCommand({ KeyId: KEY_ID, KeySpec: 'AES_256', EncryptionContext: context }),
    );
    expect(generated.CiphertextBlob).toBeDefined();

    // The identical context must round-trip...
    const decrypted = await kms.send(
      new DecryptCommand({
        CiphertextBlob: generated.CiphertextBlob,
        KeyId: KEY_ID,
        EncryptionContext: context,
      }),
    );
    expect(Buffer.from(decrypted.Plaintext as Uint8Array)).toEqual(
      Buffer.from(generated.Plaintext as Uint8Array),
    );

    // ...and a FOREIGN context must be refused. This is what makes a DEK
    // wrapped for one domain useless under another — the property the six
    // per-service keys exist to model.
    await expect(
      kms.send(
        new DecryptCommand({
          CiphertextBlob: generated.CiphertextBlob,
          KeyId: KEY_ID,
          EncryptionContext: { 'estate:kek': 'plaid/kek' },
        }),
      ),
    ).rejects.toThrow();

    // Omitting the context entirely must also be refused.
    await expect(
      kms.send(new DecryptCommand({ CiphertextBlob: generated.CiphertextBlob, KeyId: KEY_ID })),
    ).rejects.toThrow();
  });

  it('S3 IfNoneMatch:* refuses to replace an existing object, in the shape the store expects', async () => {
    const key = `conformance/${randomUUID()}`;
    const first = randomBytes(64);
    await s3.send(
      new PutObjectCommand({ Bucket: BUCKET, Key: key, Body: first, IfNoneMatch: '*' }),
    );

    // Different bytes at the same key must fail with the 412 family...
    let refused: unknown = null;
    try {
      await s3.send(
        new PutObjectCommand({
          Bucket: BUCKET,
          Key: key,
          Body: randomBytes(64),
          IfNoneMatch: '*',
        }),
      );
    } catch (err) {
      refused = err;
    }
    expect(refused).toBeInstanceOf(S3ServiceException);
    const status = (refused as S3ServiceException).$metadata.httpStatusCode;
    expect([412, 409]).toContain(status);

    // ...and the store built on that behaviour must treat a byte-identical
    // re-put as an idempotent no-op, not an error.
    const store = new S3ObjectStore(s3, BUCKET);
    await expect(store.put(key, first)).resolves.toBeUndefined();
    await expect(store.get(key)).resolves.toEqual(first);
  });

  it('S3 not-found surfaces as the exception type the 404 mapping is gated on', async () => {
    const store = new S3ObjectStore(s3, BUCKET);
    await expect(store.get(`conformance/${randomUUID()}`)).rejects.toBeInstanceOf(
      ObjectNotFoundError,
    );
  });
});
