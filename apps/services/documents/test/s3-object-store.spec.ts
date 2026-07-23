import { HeadObjectCommand, PutObjectCommand, S3ServiceException } from '@aws-sdk/client-s3';
import { ObjectConflictError, ObjectNotFoundError } from '../src/object-store';
import { S3ObjectStore } from '../src/s3-object-store';

/** Stubbed transport: the store's logic is tested, not the AWS SDK. */
function fakeClient(handler: (command: unknown) => Promise<unknown>): {
  send: jest.Mock<Promise<unknown>, [unknown]>;
} {
  return { send: jest.fn(handler) };
}

function s3Error(name: string, status: number): S3ServiceException {
  return new S3ServiceException({
    name,
    $fault: 'client',
    $metadata: { httpStatusCode: status },
  });
}

function getResponse(body: Buffer): unknown {
  return { Body: { transformToByteArray: () => Promise.resolve(new Uint8Array(body)) } };
}

describe('S3ObjectStore', () => {
  it('puts with If-None-Match:* (S3 enforces immutability server-side)', async () => {
    const client = fakeClient(() => Promise.resolve({}));
    const store = new S3ObjectStore(client, 'bucket');
    await store.put('documents/d1/v1-abc', Buffer.from('ct'));
    const command = client.send.mock.calls[0]![0] as PutObjectCommand;
    expect(command).toBeInstanceOf(PutObjectCommand);
    expect(command.input.IfNoneMatch).toBe('*');
    expect(command.input.Bucket).toBe('bucket');
  });

  it('resolves a 412 on identical bytes as an idempotent republish', async () => {
    const body = Buffer.from('same bytes');
    const client = fakeClient((command) =>
      command instanceof PutObjectCommand
        ? Promise.reject(
            Object.assign(new Error('precondition'), { $metadata: { httpStatusCode: 412 } }),
          )
        : Promise.resolve(getResponse(body)),
    );
    await expect(new S3ObjectStore(client, 'b').put('k/x', body)).resolves.toBeUndefined();
  });

  it('throws ObjectConflictError when 412 hides different content', async () => {
    const client = fakeClient((command) =>
      command instanceof PutObjectCommand
        ? Promise.reject(
            Object.assign(new Error('precondition'), { $metadata: { httpStatusCode: 412 } }),
          )
        : Promise.resolve(getResponse(Buffer.from('existing'))),
    );
    await expect(new S3ObjectStore(client, 'b').put('k/x', Buffer.from('new'))).rejects.toThrow(
      ObjectConflictError,
    );
  });

  it('gets bytes back and maps NoSuchKey to ObjectNotFoundError', async () => {
    const body = Buffer.from('ciphertext');
    const okClient = fakeClient(() => Promise.resolve(getResponse(body)));
    expect((await new S3ObjectStore(okClient, 'b').get('k/x')).equals(body)).toBe(true);

    const missingClient = fakeClient(() => Promise.reject(s3Error('NoSuchKey', 404)));
    await expect(new S3ObjectStore(missingClient, 'b').get('k/x')).rejects.toThrow(
      ObjectNotFoundError,
    );
  });

  it('exists() heads the object and maps 404 to false', async () => {
    const client = fakeClient((command) =>
      command instanceof HeadObjectCommand
        ? Promise.reject(s3Error('NotFound', 404))
        : Promise.resolve({}),
    );
    expect(await new S3ObjectStore(client, 'b').exists('k/x')).toBe(false);
  });

  it('propagates non-404 errors instead of treating them as absence', async () => {
    const client = fakeClient(() => Promise.reject(s3Error('AccessDenied', 403)));
    await expect(new S3ObjectStore(client, 'b').exists('k/x')).rejects.toThrow(S3ServiceException);
    await expect(new S3ObjectStore(client, 'b').get('k/x')).rejects.toThrow(S3ServiceException);
  });

  it('validates keys before any network call', async () => {
    const client = fakeClient(() => Promise.resolve({}));
    const store = new S3ObjectStore(client, 'b');
    await expect(store.get('../escape')).rejects.toThrow('invalid object key');
    expect(client.send).not.toHaveBeenCalled();
  });
});
