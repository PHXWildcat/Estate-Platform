import {
  DecryptCommand,
  GenerateDataKeyCommand,
  type DecryptCommandOutput,
  type GenerateDataKeyCommandOutput,
} from '@aws-sdk/client-kms';
import type { KmsKeyProvider } from '@estate/crypto';

/**
 * Production KmsKeyProvider backed by AWS KMS (CloudHSM-rooted KEKs per
 * docs/01 §4). Replaces the dev-only LocalKmsProvider. The KMS grant — not
 * the database — is the insider-threat chokepoint (docs/03 §5.3): bulk DEK
 * unwrapping shows up as bulk KMS Decrypt calls, which are rate-limited,
 * logged in CloudTrail, and circuit-broken upstream.
 *
 * Security binding: every DEK is wrapped under a KMS **encryption context**
 * derived from the domain KEK alias. KMS enforces that Decrypt supplies the
 * identical context, so a data key wrapped for one alias/domain can never be
 * unwrapped under another even if an attacker swaps ciphertext columns — the
 * AWS-side analogue of the AAD binding LocalKmsProvider uses.
 */

/** Minimal slice of KMSClient we call; real KMSClient satisfies it structurally. */
export interface KmsClientLike {
  send(command: GenerateDataKeyCommand): Promise<GenerateDataKeyCommandOutput>;
  send(command: DecryptCommand): Promise<DecryptCommandOutput>;
}

export class KmsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KmsError';
  }
}

export interface AwsKmsProviderOptions {
  /**
   * The KMS key id/alias/ARN that wraps this domain's DEKs (e.g.
   * `alias/estate-auth-kek`). One provider instance per domain KEK: a
   * deployment with separate auth/core/financial KEKs constructs one each.
   */
  keyId: string;
}

const CONTEXT_KEY = 'estate:kek';
const DEK_BYTES = 32;

export class AwsKmsProvider implements KmsKeyProvider {
  constructor(
    private readonly client: KmsClientLike,
    private readonly options: AwsKmsProviderOptions,
  ) {}

  async generateDataKey(kekAlias: string): Promise<{ plaintextKey: Buffer; wrappedKey: Buffer }> {
    const out = await this.client.send(
      new GenerateDataKeyCommand({
        KeyId: this.options.keyId,
        KeySpec: 'AES_256',
        EncryptionContext: context(kekAlias),
      }),
    );
    // Fail closed if KMS returns an unexpected shape; never fabricate key bytes.
    const plaintextKey = requireBytes(out.Plaintext, 'Plaintext');
    if (plaintextKey.length !== DEK_BYTES) {
      plaintextKey.fill(0);
      throw new KmsError('KMS returned a data key of unexpected length');
    }
    return { plaintextKey, wrappedKey: requireBytes(out.CiphertextBlob, 'CiphertextBlob') };
  }

  async unwrapDataKey(kekAlias: string, wrappedKey: Buffer): Promise<Buffer> {
    const out = await this.client.send(
      new DecryptCommand({
        // KeyId pins the key so a forged ciphertext cannot select a different
        // one; EncryptionContext must match what wrapped the key or KMS rejects.
        KeyId: this.options.keyId,
        CiphertextBlob: wrappedKey,
        EncryptionContext: context(kekAlias),
      }),
    );
    return requireBytes(out.Plaintext, 'Plaintext');
  }
}

function context(kekAlias: string): Record<string, string> {
  return { [CONTEXT_KEY]: kekAlias };
}

function requireBytes(value: Uint8Array | undefined, field: string): Buffer {
  if (value === undefined || value.length === 0) {
    // Field name only — never the (secret) bytes.
    throw new KmsError(`KMS response missing ${field}`);
  }
  return Buffer.from(value);
}
