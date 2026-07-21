# @estate/kms-aws

Production `KmsKeyProvider` (the interface from `@estate/crypto`) backed by AWS
KMS. Drop-in replacement for the dev-only `LocalKmsProvider`.

```ts
import { KMSClient } from '@aws-sdk/client-kms';
import { AwsKmsProvider } from '@estate/kms-aws';

const provider = new AwsKmsProvider(new KMSClient({ region }), {
  keyId: 'alias/estate-auth-kek',
});
// then: new FieldCrypto(provider, dekRepo, auditSink, { kekAlias: 'auth/kek/v1' })
```

## Security properties

- **Envelope encryption via `GenerateDataKey` (`AES_256`)** — the raw DEK exists
  in memory only transiently; only the KMS-wrapped blob is persisted.
- **Encryption-context binding** — every DEK is wrapped under an encryption
  context derived from the domain KEK alias (`{ 'estate:kek': <alias> }`). KMS
  refuses `Decrypt` unless the identical context is supplied, so a wrapped key
  for one alias/domain cannot be unwrapped under another (the AWS analogue of
  the AAD binding in `LocalKmsProvider`). Verified in tests.
- **`KeyId` pinned on Decrypt** so a forged ciphertext cannot select a
  different key.
- **Fails closed** — a KMS response missing the plaintext, or a data key of
  unexpected length, throws `KmsError` (field names only, never key bytes)
  rather than returning fabricated material.

## Operational notes

- One provider instance per domain KEK (auth / core / financial / …). The
  KMS grant, not the database, is the insider-threat chokepoint (docs/03 §5.3):
  bulk unwrapping surfaces as bulk `Decrypt` calls — rate-limit, CloudTrail-log,
  and circuit-break them upstream.
- Region, credentials (IRSA), and retry policy come from the injected
  `KMSClient`; this package does not construct one.

## TODO

- KEK rotation helper (re-wrap DEKs on annual KEK rotation).
- Optional `Recipient`/attestation support for CloudHSM enclaves.
