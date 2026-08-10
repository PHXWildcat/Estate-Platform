/**
 * Sealing a value to a grantee's public key (ECDH P-256 + HKDF + AES-256-GCM).
 *
 * Emergency access needs the owner to hand each designated contact a piece of
 * the recovery key without either the server or the other contacts being able
 * to read it, and without the grantee being online at the time. That is
 * public-key encryption, and P-256 ECDH is the only asymmetric primitive
 * WebCrypto offers that keeps this package dependency-free.
 *
 * Wire format: [1B version][2B ephemeral key length BE][ephemeral public key][AEAD envelope]
 *
 * KEY AUTHENTICITY IS THE HARD PART, and it is not solved here. This module
 * encrypts to whatever public key it is handed; binding that key to a person is
 * the caller's job, which is why every seal takes an AAD that includes the
 * recipient key's fingerprint (see `recovery.ts`) and why the owner is asked to
 * verify that fingerprint out of band. Without that step a malicious server
 * substitutes its own key at configure time and the escrow protects nothing.
 */

import { open, seal, VaultCryptoError, VaultDecryptionError } from './aead.js';
import { concatBytes, sha256, source, utf8 } from './bytes.js';

export const ECIES_VERSION = 0x01;
const CURVE = { name: 'ECDH', namedCurve: 'P-256' } as const;
/** Uncompressed P-256 point: 0x04 || X(32) || Y(32). */
export const PUBLIC_KEY_BYTES = 65;

export class EciesError extends VaultCryptoError {
  constructor(detail: string) {
    super(`ecies failure: ${detail}`);
    this.name = 'EciesError';
  }
}

export interface RecoveryKeyPair {
  /** Raw uncompressed point, safe to publish. */
  readonly publicKey: Uint8Array;
  /** PKCS#8 bytes, to be wrapped under the holder's own master key. */
  readonly privateKey: Uint8Array;
}

export async function generateRecoveryKeyPair(): Promise<RecoveryKeyPair> {
  const pair = await crypto.subtle.generateKey(CURVE, true, ['deriveBits']);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return { publicKey, privateKey };
}

function assertPublicKey(bytes: Uint8Array): void {
  if (bytes.length !== PUBLIC_KEY_BYTES || bytes[0] !== 0x04) {
    throw new EciesError('invalid recipient public key');
  }
}

/** Symbols in a fingerprint; 5 bits each over the Crockford alphabet. */
export const FINGERPRINT_SYMBOLS = 16;
const FINGERPRINT_GROUP = 4;

/**
 * A short, human-readable fingerprint of a public key, for the owner to confirm
 * with the grantee over a channel the platform does not control (docs/03 §5.2).
 * Safety-number style: 16 characters in four groups, read aloud in seconds.
 *
 * The width is a security parameter, not a display choice. This is the SOLE
 * defense against a malicious server substituting its own key at configure
 * time — nothing server-side can check it, because the server is the adversary
 * in that scenario. 16 symbols is 80 bits, so a second-preimage grind costs
 * 2^80 P-256 keygens. An earlier revision emitted 10 symbols (50 bits), which
 * a determined attacker could grind offline in GPU-days against a targeted
 * user; the M6 security review caught it.
 */
export async function publicKeyFingerprint(publicKey: Uint8Array): Promise<string> {
  assertPublicKey(publicKey);
  const digest = await sha256(utf8('estate.vault.grantee-key.v1'), publicKey);
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  // Consume the digest as a bitstream rather than one symbol per byte, so all
  // 80 bits come from distinct digest bits.
  let bits = 0;
  let accumulator = 0;
  let text = '';
  for (const byte of digest) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5 && text.length < FINGERPRINT_SYMBOLS) {
      bits -= 5;
      text += alphabet[(accumulator >> bits) & 0x1f];
    }
    if (text.length === FINGERPRINT_SYMBOLS) break;
  }

  const groups: string[] = [];
  for (let i = 0; i < text.length; i += FINGERPRINT_GROUP) {
    groups.push(text.slice(i, i + FINGERPRINT_GROUP));
  }
  return groups.join('-');
}

export async function publicKeyDigest(publicKey: Uint8Array): Promise<Uint8Array> {
  assertPublicKey(publicKey);
  return sha256(publicKey);
}

async function deriveSharedKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  ephemeralPublic: Uint8Array,
  recipientPublic: Uint8Array,
): Promise<CryptoKey> {
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256),
  );
  const hkdfKey = await crypto.subtle.importKey('raw', source(shared), 'HKDF', false, [
    'deriveBits',
  ]);
  // Salt binds BOTH public keys into the derivation, so a shared secret can
  // never be reused across a different pairing.
  const salt = await sha256(concatBytes(ephemeralPublic, recipientPublic));
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: source(salt),
      info: source(utf8('estate.vault.ecies.v1')),
    },
    hkdfKey,
    256,
  );
  shared.fill(0);
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function sealToPublicKey(
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  assertPublicKey(recipientPublicKey);
  const recipient = await crypto.subtle.importKey(
    'raw',
    source(recipientPublicKey),
    CURVE,
    false,
    [],
  );
  const ephemeral = await crypto.subtle.generateKey(CURVE, true, ['deriveBits']);
  const ephemeralPublic = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));

  const key = await deriveSharedKey(
    ephemeral.privateKey,
    recipient,
    ephemeralPublic,
    recipientPublicKey,
  );
  const envelope = await seal(key, plaintext, aad);

  const out = new Uint8Array(3 + ephemeralPublic.length + envelope.length);
  out[0] = ECIES_VERSION;
  out[1] = (ephemeralPublic.length >> 8) & 0xff;
  out[2] = ephemeralPublic.length & 0xff;
  out.set(ephemeralPublic, 3);
  out.set(envelope, 3 + ephemeralPublic.length);
  return out;
}

export async function openWithPrivateKey(
  recipientPrivateKeyPkcs8: Uint8Array,
  sealed: Uint8Array,
  aad: string,
): Promise<Uint8Array> {
  if (sealed.length < 3 || sealed[0] !== ECIES_VERSION) throw new VaultDecryptionError();
  const ephemeralLength = (sealed[1]! << 8) | sealed[2]!;
  const bodyStart = 3 + ephemeralLength;
  if (bodyStart > sealed.length) throw new VaultDecryptionError();

  const ephemeralPublic = sealed.subarray(3, bodyStart);
  if (ephemeralPublic.length !== PUBLIC_KEY_BYTES) throw new VaultDecryptionError();

  let privateKey: CryptoKey;
  let ephemeral: CryptoKey;
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      source(recipientPrivateKeyPkcs8),
      CURVE,
      false,
      ['deriveBits'],
    );
    ephemeral = await crypto.subtle.importKey('raw', source(ephemeralPublic), CURVE, false, []);
  } catch {
    throw new VaultDecryptionError();
  }

  const recipientPublic = await recoverRecipientPublicKey(recipientPrivateKeyPkcs8);
  const key = await deriveSharedKey(privateKey, ephemeral, ephemeralPublic, recipientPublic);
  return open(key, sealed.subarray(bodyStart), aad);
}

/**
 * The salt binds the recipient's public key, so opening needs it too. It is
 * carried inside the PKCS#8 private key, which WebCrypto will surface via JWK.
 */
async function recoverRecipientPublicKey(privateKeyPkcs8: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('pkcs8', source(privateKeyPkcs8), CURVE, true, [
    'deriveBits',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.x || !jwk.y) throw new EciesError('private key carries no public point');
  const point = new Uint8Array(PUBLIC_KEY_BYTES);
  point[0] = 0x04;
  point.set(base64UrlToBytes(jwk.x), 1);
  point.set(base64UrlToBytes(jwk.y), 33);
  return point;
}

function base64UrlToBytes(text: string): Uint8Array {
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}
