/**
 * @estate/vault-crypto — Zone A client-side cryptography.
 *
 * ZERO runtime dependencies, by requirement rather than by taste: this code
 * runs on the user's device, where docs/03 rates compromise (TB6, risk #4) as
 * Critical, and docs/04 boundary rule 3 makes the dependency-free surface the
 * control. `test/zero-dependency.spec.ts` enforces it, and an ESLint fence
 * catches it while typing.
 *
 * This package must NEVER import `@estate/crypto` — that is the server-side
 * Zone B envelope layer, which handles plaintext DEKs and KMS material.
 */

export {
  ENVELOPE_VERSION,
  KEY_LENGTH,
  NONCE_LENGTH,
  VaultCryptoError,
  VaultDecryptionError,
  generateAesKey,
  importAesKey,
  open,
  seal,
  unwrapAesKey,
  type AesUsage,
} from './aead.js';

export { bigIntToBytes, bytesToBigInt, constantTimeEqual, modPow } from './bigint.js';

export {
  ECIES_VERSION,
  EciesError,
  FINGERPRINT_SYMBOLS,
  PUBLIC_KEY_BYTES,
  generateRecoveryKeyPair,
  openWithPrivateKey,
  publicKeyDigest,
  publicKeyFingerprint,
  sealToPublicKey,
  type RecoveryKeyPair,
} from './ecies.js';

export {
  RECOVERY_KEY_BYTES,
  createEscrow,
  recoverMasterKey,
  recoveryWrapAad,
  shareAad,
  type EscrowGrantee,
  type EscrowMaterial,
  type HeldShare,
  type SealedShare,
} from './recovery.js';

export {
  MAX_SHARES,
  ShamirError,
  combine,
  decodeShare,
  encodeShare,
  split,
  type Share,
} from './shamir.js';

export {
  concatBytes,
  fromBase64,
  randomBytes,
  sha256,
  toBase64,
  utf8,
  wipe,
  xorBytes,
} from './bytes.js';

export {
  SECRET_KEY_BYTES,
  SecretKeyFormatError,
  formatSecretKey,
  generateSecretKey,
  parseSecretKey,
  secretKeyFromBase64,
  secretKeyToBase64,
} from './format.js';

export {
  ITEM_BLOB_VERSION,
  decryptItem,
  encryptItem,
  itemContentAad,
  itemKeyAad,
  type VaultItemRef,
} from './items.js';

export {
  CIPHER_ID,
  DEFAULT_ITERATIONS,
  DERIVED_LENGTH,
  KDF_ALG,
  KDF_VERSION,
  MAX_ITERATIONS,
  MIN_ITERATIONS,
  SALT_LENGTH,
  SRP_GROUP_ID,
  VaultParameterError,
  assertSupportedKdfParams,
  defaultKdfParams,
  deriveHkdf,
  deriveKeysetAuthKey,
  deriveVaultKeys,
  hmacSha256,
  type KdfParams,
  type VaultKeyMaterial,
} from './kdf.js';

export {
  MASTER_KEY_BYTES,
  buildKeysetChange,
  canonicalKeysetPayload,
  createVaultEnrollment,
  exportMasterKeyBytes,
  finishUnlock,
  keysetProof,
  masterKeyAad,
  prepareUnlock,
  proveUnlock,
  verifyKeysetProof,
  type UnlockPreparation,
  type UnlockedVault,
  type VaultEnrollment,
  type VaultKeysetPayload,
} from './keyset.js';

export {
  SRP_ELEMENT_BYTES,
  SRP_EPHEMERAL_BYTES,
  SRP_G,
  SRP_N,
  SRP_SALT_BYTES,
  SrpError,
  computeClientSession,
  computeVerifier,
  createClientEphemeral,
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  srpPrivateKey,
  verifyClientSession,
  verifyServerProof,
  type ClientEphemeral,
  type ClientSession,
  type ServerEphemeral,
  type ServerSession,
} from './srp.js';
