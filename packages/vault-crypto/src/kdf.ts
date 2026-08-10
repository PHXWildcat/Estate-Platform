/**
 * Two-Secret Key Derivation (docs/01 §4: `key = HKDF(2SKD(password, secret-key))`).
 *
 * The vault password alone never derives anything. Every derived key mixes the
 * password with a 128-bit Secret Key that exists only on the user's devices and
 * is never transmitted, so material the server holds (the SRP verifier, the
 * wrapped master key) cannot be attacked offline even with unlimited compute
 * and a perfect password guess. That is the property that makes Zone A survive
 * a full server compromise, and it is why the password KDF is PBKDF2 rather
 * than Argon2id: WebCrypto has no Argon2, and adding a WASM Argon2 to this
 * package would trade a real, load-bearing property (a near-zero audit surface
 * on the user's device — docs/04 boundary rule 3) for a defense the Secret Key
 * already provides. Approved deviation from docs/00, recorded in the CLAUDE.md
 * decision log; `kdfParams` is versioned so Argon2id can be adopted later
 * without a migration.
 *
 * One PBKDF2 pass feeds both outputs (the account unlock key and the SRP
 * private key) through domain-separated HKDF expansions. Deriving them with two
 * independent PBKDF2 runs would double the unlock latency for no security gain.
 */

import { fromBase64, source, utf8, wipe, xorBytes } from './bytes.js';
import { importAesKey, VaultCryptoError } from './aead.js';

export const KDF_VERSION = 1;
export const KDF_ALG = 'pbkdf2-sha256';
export const SRP_GROUP_ID = 'rfc5054-4096';
export const CIPHER_ID = 'aes-256-gcm';
export const SALT_LENGTH = 16;
export const DERIVED_LENGTH = 32;

/**
 * OWASP's 2023 floor for PBKDF2-HMAC-SHA256. The client refuses anything below
 * it even when the server says otherwise — see `assertSupportedKdfParams`.
 */
export const MIN_ITERATIONS = 600_000;
export const DEFAULT_ITERATIONS = 650_000;
/** Upper bound so a hostile server cannot turn "unlock" into a device freeze. */
export const MAX_ITERATIONS = 10_000_000;

export interface KdfParams {
  readonly v: typeof KDF_VERSION;
  readonly alg: typeof KDF_ALG;
  readonly iterations: number;
  /** base64, 16 bytes. Distinct from the SRP salt, which is its own column. */
  readonly aukSalt: string;
  readonly srpGroup: typeof SRP_GROUP_ID;
  readonly cipher: typeof CIPHER_ID;
}

export class VaultParameterError extends VaultCryptoError {
  constructor(detail: string) {
    super(`unsupported vault parameters: ${detail}`);
    this.name = 'VaultParameterError';
  }
}

export function defaultKdfParams(aukSalt: string, iterations = DEFAULT_ITERATIONS): KdfParams {
  return {
    v: KDF_VERSION,
    alg: KDF_ALG,
    iterations,
    aukSalt,
    srpGroup: SRP_GROUP_ID,
    cipher: CIPHER_ID,
  };
}

/**
 * Validate parameters that arrived from the server before deriving anything.
 *
 * This is a load-bearing control, not defensive tidiness. The client fetches
 * `kdfParams` and the SRP group from the server at unlock time, so a malicious
 * or compromised server (docs/03: malicious platform insider — the adversary
 * Zone A exists to defeat) could otherwise hand back a degenerate SRP group and
 * recover the SRP private key by small-subgroup confinement, or drop the
 * iteration count and silently void the password half of the derivation.
 * Everything is pinned to the one supported profile and rejected before any
 * modular exponentiation happens.
 */
export function assertSupportedKdfParams(value: unknown): KdfParams {
  if (typeof value !== 'object' || value === null) throw new VaultParameterError('not an object');
  const params = value as Record<string, unknown>;
  if (params['v'] !== KDF_VERSION) throw new VaultParameterError('version');
  if (params['alg'] !== KDF_ALG) throw new VaultParameterError('algorithm');
  if (params['srpGroup'] !== SRP_GROUP_ID) throw new VaultParameterError('srp group');
  if (params['cipher'] !== CIPHER_ID) throw new VaultParameterError('cipher');

  const iterations = params['iterations'];
  if (
    typeof iterations !== 'number' ||
    !Number.isInteger(iterations) ||
    iterations < MIN_ITERATIONS ||
    iterations > MAX_ITERATIONS
  ) {
    throw new VaultParameterError('iterations');
  }

  const aukSalt = params['aukSalt'];
  if (typeof aukSalt !== 'string') throw new VaultParameterError('auk salt');
  try {
    if (fromBase64(aukSalt).length !== SALT_LENGTH) throw new VaultParameterError('auk salt');
  } catch (err) {
    // A malformed salt is a rejected parameter like any other; callers should
    // not have to catch two error types to handle a hostile server.
    if (err instanceof VaultParameterError) throw err;
    throw new VaultParameterError('auk salt');
  }

  return {
    v: KDF_VERSION,
    alg: KDF_ALG,
    iterations,
    aukSalt,
    srpGroup: SRP_GROUP_ID,
    cipher: CIPHER_ID,
  };
}

async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: string,
  length = DERIVED_LENGTH,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', source(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: source(salt), info: source(utf8(info)) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  // NFKD so the same typed password derives the same key on every platform and
  // keyboard. Pinned by `KDF_VERSION`; changing it would silently lock users out.
  const material = utf8(password.normalize('NFKD'));
  const key = await crypto.subtle.importKey('raw', source(material), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: source(salt), iterations },
    key,
    DERIVED_LENGTH * 8,
  );
  wipe(material);
  return new Uint8Array(bits);
}

export interface VaultKeyMaterial {
  /** Account unlock key: wraps (and unwraps) the master key. Non-extractable. */
  readonly auk: CryptoKey;
  /** SRP private key `x`, as raw bytes; `srp.ts` reduces it into the group. */
  readonly srpX: Uint8Array;
}

/**
 * The 2SKD core. `kdfParams` MUST already have been through
 * `assertSupportedKdfParams` when it came from the server.
 */
export async function deriveVaultKeys(input: {
  readonly userId: string;
  readonly password: string;
  readonly secretKey: Uint8Array;
  readonly kdfParams: KdfParams;
  readonly srpSalt: Uint8Array;
}): Promise<VaultKeyMaterial> {
  const { userId, password, secretKey, kdfParams, srpSalt } = input;
  const aukSalt = fromBase64(kdfParams.aukSalt);

  // Bind the PBKDF2 salt to the account so two users with the same password and
  // the same stored salt still derive different keys.
  const saltPrime = await hkdf(utf8(userId), aukSalt, 'estate.vault.2skd.salt.v1');
  const passwordKey = await pbkdf2(password, saltPrime, kdfParams.iterations);
  const secretKeyPart = await hkdf(secretKey, utf8(userId), 'estate.vault.2skd.sk.v1');

  // XOR is the 1Password construction: the result is unrecoverable without BOTH
  // inputs, so a cracked password yields nothing on its own.
  const base = xorBytes(passwordKey, secretKeyPart);
  wipe(passwordKey, secretKeyPart, saltPrime);

  const aukBytes = await hkdf(base, aukSalt, 'estate.vault.auk.v1');
  const srpX = await hkdf(base, srpSalt, 'estate.vault.srp-x.v1');
  wipe(base);

  const auk = await importAesKey(aukBytes, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], false);
  wipe(aukBytes);

  return { auk, srpX };
}

/**
 * Derive the key that authenticates a keyset replacement, from the SRP session
 * key. Both sides compute this independently after a successful handshake; see
 * `keyset.ts` for why replacing a keyset needs proof of the CURRENT password
 * rather than just a bearer token.
 */
export async function deriveKeysetAuthKey(
  sessionKey: Uint8Array,
  vaultSessionId: string,
): Promise<Uint8Array> {
  return hkdf(sessionKey, utf8(vaultSessionId), 'estate.vault.keyset-auth.v1');
}

export async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const macKey = await crypto.subtle.importKey(
    'raw',
    source(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', macKey, source(message)));
}

/** Exported for tests and for `keyset.ts`; keeps the HKDF wiring in one place. */
export { hkdf as deriveHkdf };
