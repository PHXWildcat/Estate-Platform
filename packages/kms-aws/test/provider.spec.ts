import { randomBytes, randomUUID } from 'node:crypto';
import {
  DecryptCommand,
  GenerateDataKeyCommand,
  type DecryptCommandOutput,
  type GenerateDataKeyCommandOutput,
} from '@aws-sdk/client-kms';
import { AwsKmsProvider, KmsError, type KmsClientLike } from '../src/provider';

/**
 * Fake KMS that models the two guarantees we depend on: it returns a random
 * 256-bit data key + an opaque wrapped blob, and — critically — Decrypt fails
 * unless the EncryptionContext matches what GenerateDataKey used (this is the
 * real KMS behavior our security binding relies on).
 */
class FakeKms implements KmsClientLike {
  private readonly store = new Map<string, { key: Buffer; context: string }>();
  readonly generated: GenerateDataKeyCommand[] = [];
  keyLengthOverride: number | null = null;
  dropPlaintext = false;

  send(command: GenerateDataKeyCommand): Promise<GenerateDataKeyCommandOutput>;
  send(command: DecryptCommand): Promise<DecryptCommandOutput>;
  send(command: GenerateDataKeyCommand | DecryptCommand): Promise<unknown> {
    if (command instanceof GenerateDataKeyCommand) {
      this.generated.push(command);
      const key = randomBytes(this.keyLengthOverride ?? 32);
      const blobId = randomUUID();
      this.store.set(blobId, {
        key,
        context: JSON.stringify(command.input.EncryptionContext ?? {}),
      });
      return Promise.resolve({
        Plaintext: this.dropPlaintext ? undefined : new Uint8Array(key),
        CiphertextBlob: Buffer.from(blobId, 'utf8'),
        $metadata: {},
      } satisfies GenerateDataKeyCommandOutput);
    }
    const blobId = Buffer.from(command.input.CiphertextBlob!).toString('utf8');
    const entry = this.store.get(blobId);
    if (!entry) {
      return Promise.reject(new Error('NotFoundException'));
    }
    if (entry.context !== JSON.stringify(command.input.EncryptionContext ?? {})) {
      // KMS InvalidCiphertextException when the encryption context differs.
      return Promise.reject(new Error('InvalidCiphertextException'));
    }
    return Promise.resolve({
      Plaintext: new Uint8Array(entry.key),
      $metadata: {},
    } satisfies DecryptCommandOutput);
  }
}

const KEY_ID = 'alias/estate-auth-kek';

describe('AwsKmsProvider', () => {
  it('generates an AES-256 data key bound to the KEK alias as encryption context', async () => {
    const kms = new FakeKms();
    const provider = new AwsKmsProvider(kms, { keyId: KEY_ID });

    const { plaintextKey, wrappedKey } = await provider.generateDataKey('auth/kek/v1');
    expect(plaintextKey).toHaveLength(32);
    expect(wrappedKey.length).toBeGreaterThan(0);

    const cmd = kms.generated[0]!;
    expect(cmd.input.KeyId).toBe(KEY_ID);
    expect(cmd.input.KeySpec).toBe('AES_256');
    expect(cmd.input.EncryptionContext).toEqual({ 'estate:kek': 'auth/kek/v1' });
  });

  it('round-trips: a key wrapped under an alias unwraps under the same alias', async () => {
    const provider = new AwsKmsProvider(new FakeKms(), { keyId: KEY_ID });
    const { plaintextKey, wrappedKey } = await provider.generateDataKey('auth/kek/v1');
    const unwrapped = await provider.unwrapDataKey('auth/kek/v1', wrappedKey);
    expect(unwrapped).toEqual(plaintextKey);
  });

  it('refuses to unwrap under a different alias (encryption-context binding)', async () => {
    const provider = new AwsKmsProvider(new FakeKms(), { keyId: KEY_ID });
    const { wrappedKey } = await provider.generateDataKey('auth/kek/v1');
    await expect(provider.unwrapDataKey('core/kek/v1', wrappedKey)).rejects.toThrow(
      /InvalidCiphertext/,
    );
  });

  it('fails closed if KMS omits the plaintext key', async () => {
    const kms = new FakeKms();
    kms.dropPlaintext = true;
    const provider = new AwsKmsProvider(kms, { keyId: KEY_ID });
    await expect(provider.generateDataKey('auth/kek/v1')).rejects.toThrow(KmsError);
  });

  it('rejects a data key of unexpected length without returning it', async () => {
    const kms = new FakeKms();
    kms.keyLengthOverride = 16;
    const provider = new AwsKmsProvider(kms, { keyId: KEY_ID });
    await expect(provider.generateDataKey('auth/kek/v1')).rejects.toThrow(/unexpected length/);
  });

  it('never leaks key material in error messages', async () => {
    const kms = new FakeKms();
    kms.dropPlaintext = true;
    const provider = new AwsKmsProvider(kms, { keyId: KEY_ID });
    await expect(provider.generateDataKey('auth/kek/v1')).rejects.toThrow(
      'KMS response missing Plaintext',
    );
  });
});
