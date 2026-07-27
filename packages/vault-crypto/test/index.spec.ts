/**
 * Public-surface guard (the @estate/auth-guard precedent): the barrel is the
 * contract other packages compile against, so a symbol silently dropped from it
 * should fail here rather than in a consumer's build.
 */
import * as vaultCrypto from '../src/index';

const EXPECTED_EXPORTS = [
  // aead
  'ENVELOPE_VERSION',
  'KEY_LENGTH',
  'NONCE_LENGTH',
  'VaultCryptoError',
  'VaultDecryptionError',
  'generateAesKey',
  'importAesKey',
  'open',
  'seal',
  'unwrapAesKey',
  // bigint
  'bigIntToBytes',
  'bytesToBigInt',
  'constantTimeEqual',
  'modPow',
  // bytes
  'concatBytes',
  'fromBase64',
  'randomBytes',
  'sha256',
  'toBase64',
  'utf8',
  'wipe',
  'xorBytes',
  // format
  'SECRET_KEY_BYTES',
  'SecretKeyFormatError',
  'formatSecretKey',
  'generateSecretKey',
  'parseSecretKey',
  'secretKeyFromBase64',
  'secretKeyToBase64',
  // items
  'ITEM_BLOB_VERSION',
  'decryptItem',
  'encryptItem',
  'itemContentAad',
  'itemKeyAad',
  // kdf
  'CIPHER_ID',
  'DEFAULT_ITERATIONS',
  'DERIVED_LENGTH',
  'KDF_ALG',
  'KDF_VERSION',
  'MAX_ITERATIONS',
  'MIN_ITERATIONS',
  'SALT_LENGTH',
  'SRP_GROUP_ID',
  'VaultParameterError',
  'assertSupportedKdfParams',
  'defaultKdfParams',
  'deriveHkdf',
  'deriveKeysetAuthKey',
  'deriveVaultKeys',
  'hmacSha256',
  // keyset
  'MASTER_KEY_BYTES',
  'buildKeysetChange',
  'canonicalKeysetPayload',
  'createVaultEnrollment',
  'exportMasterKeyBytes',
  'finishUnlock',
  'keysetProof',
  'masterKeyAad',
  'prepareUnlock',
  'proveUnlock',
  'verifyKeysetProof',
  // srp
  'SRP_ELEMENT_BYTES',
  'SRP_EPHEMERAL_BYTES',
  'SRP_G',
  'SRP_N',
  'SRP_SALT_BYTES',
  'SrpError',
  'computeClientSession',
  'computeVerifier',
  'createClientEphemeral',
  'createServerEphemeral',
  'decodeGroupElement',
  'encodeGroupElement',
  'srpPrivateKey',
  'verifyClientSession',
  'verifyServerProof',
];

describe('public surface', () => {
  it.each(EXPECTED_EXPORTS)('exports %s', (name) => {
    expect(vaultCrypto).toHaveProperty(name);
  });

  it('exports nothing beyond the documented surface', () => {
    expect(Object.keys(vaultCrypto).sort()).toEqual([...EXPECTED_EXPORTS].sort());
  });
});
