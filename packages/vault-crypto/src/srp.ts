/**
 * SRP-6a, the "SRP for auth" half of docs/01 §4.
 *
 * The point of SRP here is that the vault password never reaches the server in
 * any form — not as a hash, not over TLS, not in a request body it could log.
 * The server stores only a verifier and can neither replay it against another
 * server nor use it to derive the account unlock key.
 *
 * Both roles live in this one client-side package on purpose: there is a single
 * vector-pinned implementation to audit instead of two that can drift, and the
 * vault service (which may import client code, never the reverse) uses the
 * server half. Hand-writing this on `bigint` follows the precedent set by the
 * node:crypto Plaid webhook verifier, the deterministic template renderer, and
 * the node:net clamd client: on a security-critical path, a small auditable
 * primitive beats a dependency.
 *
 * Profile (pinned by `KDF_VERSION` = 1 — client and server are the same code,
 * so what matters is that it never silently changes):
 *   group  RFC 5054 Appendix A, 4096-bit, g = 5, SHA-256
 *   k      H(PAD(N) || PAD(g))
 *   x      NOT RFC 5054's H(s | H(I ":" p)) — it is the 2SKD output (kdf.ts), so
 *          the verifier inherits the Secret Key's 128 bits and a stolen
 *          database cannot even begin an offline dictionary attack
 *   u      H(PAD(A) || PAD(B))
 *   K      H(PAD(S))
 *   M1     H( (H(PAD(N)) XOR H(PAD(g))) || H(userId) || salt || PAD(A) || PAD(B) || K )
 *   M2     H( PAD(A) || M1 || K )
 * Identity `I` is the user's UUID, never their email — same rule as identity's
 * TOTP provisioning URI.
 */

import { bigIntToBytes, bytesToBigInt, constantTimeEqual, modPow } from './bigint.js';
import { fromBase64, randomBytes, sha256, toBase64, utf8, xorBytes } from './bytes.js';
import { VaultCryptoError } from './aead.js';

/**
 * RFC 5054 Appendix A, 4096-bit group (the RFC 3526 group-16 prime with g = 5).
 * Laid out in the RFC's 8-hex-digit columns so it can be diffed against the
 * source document by eye; `srp.spec.ts` runs Fermat checks over it so a
 * transcription slip fails the build rather than weakening the group silently.
 */
const N_HEX = [
  'FFFFFFFF',
  'FFFFFFFF',
  'C90FDAA2',
  '2168C234',
  'C4C6628B',
  '80DC1CD1',
  '29024E08',
  '8A67CC74',
  '020BBEA6',
  '3B139B22',
  '514A0879',
  '8E3404DD',
  'EF9519B3',
  'CD3A431B',
  '302B0A6D',
  'F25F1437',
  '4FE1356D',
  '6D51C245',
  'E485B576',
  '625E7EC6',
  'F44C42E9',
  'A637ED6B',
  '0BFF5CB6',
  'F406B7ED',
  'EE386BFB',
  '5A899FA5',
  'AE9F2411',
  '7C4B1FE6',
  '49286651',
  'ECE45B3D',
  'C2007CB8',
  'A163BF05',
  '98DA4836',
  '1C55D39A',
  '69163FA8',
  'FD24CF5F',
  '83655D23',
  'DCA3AD96',
  '1C62F356',
  '208552BB',
  '9ED52907',
  '7096966D',
  '670C354E',
  '4ABC9804',
  'F1746C08',
  'CA18217C',
  '32905E46',
  '2E36CE3B',
  'E39E772C',
  '180E8603',
  '9B2783A2',
  'EC07A28F',
  'B5C55DF0',
  '6F4C52C9',
  'DE2BCBF6',
  '95581718',
  '3995497C',
  'EA956AE5',
  '15D22618',
  '98FA0510',
  '15728E5A',
  '8AAAC42D',
  'AD33170D',
  '04507A33',
  'A85521AB',
  'DF1CBA64',
  'ECFB8504',
  '58DBEF0A',
  '8AEA7157',
  '5D060C7D',
  'B3970F85',
  'A6E1E4C7',
  'ABF5AE8C',
  'DB0933D7',
  '1E8C94E0',
  '4A25619D',
  'CEE3D226',
  '1AD2EE6B',
  'F12FFA06',
  'D98A0864',
  'D8760273',
  '3EC86A64',
  '521F2B18',
  '177B200C',
  'BBE11757',
  '7A615D6C',
  '770988C0',
  'BAD946E2',
  '08E24FA0',
  '74E5AB31',
  '43DB5BFC',
  'E0FD108E',
  '4B82D120',
  'A9210801',
  '1A723C12',
  'A787E6D7',
  '88719A10',
  'BDBA5B26',
  '99C32718',
  '6AF4E23C',
  '1A946834',
  'B6150BDA',
  '2583E9CA',
  '2AD44CE8',
  'DBBBC2DB',
  '04DE8EF9',
  '2E8EFC14',
  '1FBECAA6',
  '287C5947',
  '4E6BC05D',
  '99B2964F',
  'A090C3A2',
  '233BA186',
  '515BE7ED',
  '1F612970',
  'CEE2D7AF',
  'B81BDD76',
  '2170481C',
  'D0069127',
  'D5B05AA9',
  '93B4EA98',
  '8D8FDDC1',
  '86FFB7DC',
  '90A6C08F',
  '4DF435C9',
  '34063199',
  'FFFFFFFF',
  'FFFFFFFF',
].join('');

export const SRP_N = BigInt(`0x${N_HEX}`);
export const SRP_G = 5n;
/** Every group element is hashed and transmitted padded to this width. */
export const SRP_ELEMENT_BYTES = 512;
/** RFC 5054: the ephemeral secrets a and b SHOULD be at least 256 bits. */
export const SRP_EPHEMERAL_BYTES = 32;
export const SRP_SALT_BYTES = 16;

export class SrpError extends VaultCryptoError {
  constructor(detail: string) {
    super(`srp failure: ${detail}`);
    this.name = 'SrpError';
  }
}

function pad(value: bigint): Uint8Array {
  return bigIntToBytes(value, SRP_ELEMENT_BYTES);
}

let cachedK: Promise<bigint> | null = null;
async function multiplierK(): Promise<bigint> {
  cachedK ??= (async (): Promise<bigint> => bytesToBigInt(await sha256(pad(SRP_N), pad(SRP_G))))();
  return cachedK;
}

/**
 * Reject anything outside [1, N-1] and anything congruent to zero. A reflected
 * or degenerate group element is the classic way to force the shared secret to
 * a value the attacker already knows, so both roles check their peer's element
 * before any exponentiation.
 */
function assertInGroup(value: bigint, label: string): bigint {
  if (value <= 0n || value >= SRP_N || value % SRP_N === 0n) throw new SrpError(`invalid ${label}`);
  return value;
}

export function encodeGroupElement(value: bigint): string {
  return toBase64(pad(value));
}

export function decodeGroupElement(text: string, label: string): bigint {
  const bytes = fromBase64(text);
  if (bytes.length !== SRP_ELEMENT_BYTES) throw new SrpError(`invalid ${label} length`);
  return assertInGroup(bytesToBigInt(bytes), label);
}

/** Reduce the 2SKD output into the group. */
export function srpPrivateKey(srpX: Uint8Array): bigint {
  const x = bytesToBigInt(srpX) % SRP_N;
  if (x === 0n) throw new SrpError('degenerate private key');
  return x;
}

export function computeVerifier(x: bigint): bigint {
  return modPow(SRP_G, x, SRP_N);
}

function randomExponent(): bigint {
  for (;;) {
    const candidate = bytesToBigInt(randomBytes(SRP_EPHEMERAL_BYTES)) % SRP_N;
    if (candidate > 1n) return candidate;
  }
}

export interface ClientEphemeral {
  readonly a: bigint;
  readonly A: bigint;
}

export function createClientEphemeral(): ClientEphemeral {
  for (;;) {
    const a = randomExponent();
    const A = modPow(SRP_G, a, SRP_N);
    if (A % SRP_N !== 0n) return { a, A };
  }
}

export interface ServerEphemeral {
  readonly b: bigint;
  readonly B: bigint;
}

export async function createServerEphemeral(verifier: bigint): Promise<ServerEphemeral> {
  const k = await multiplierK();
  for (;;) {
    const b = randomExponent();
    const B = (k * verifier + modPow(SRP_G, b, SRP_N)) % SRP_N;
    if (B % SRP_N !== 0n) return { b, B };
  }
}

async function scramblingParameter(A: bigint, B: bigint): Promise<bigint> {
  const u = bytesToBigInt(await sha256(pad(A), pad(B)));
  // u = 0 would make the session key independent of the verifier, i.e. turn the
  // handshake into an unauthenticated Diffie-Hellman.
  if (u % SRP_N === 0n) throw new SrpError('degenerate scrambling parameter');
  return u;
}

async function proofs(input: {
  readonly userId: string;
  readonly salt: Uint8Array;
  readonly A: bigint;
  readonly B: bigint;
  readonly S: bigint;
}): Promise<{ M1: Uint8Array; M2: Uint8Array; sessionKey: Uint8Array }> {
  const sessionKey = await sha256(pad(input.S));
  const hashN = await sha256(pad(SRP_N));
  const hashG = await sha256(pad(SRP_G));
  const hashIdentity = await sha256(utf8(input.userId));
  const M1 = await sha256(
    xorBytes(hashN, hashG),
    hashIdentity,
    input.salt,
    pad(input.A),
    pad(input.B),
    sessionKey,
  );
  const M2 = await sha256(pad(input.A), M1, sessionKey);
  return { M1, M2, sessionKey };
}

export interface ClientSession {
  /** Proof of password knowledge, sent to the server. */
  readonly M1: Uint8Array;
  /** What the server's reply must equal — proves the server holds the verifier. */
  readonly expectedM2: Uint8Array;
  readonly sessionKey: Uint8Array;
}

export async function computeClientSession(input: {
  readonly userId: string;
  readonly salt: Uint8Array;
  readonly x: bigint;
  readonly ephemeral: ClientEphemeral;
  readonly B: bigint;
}): Promise<ClientSession> {
  const B = assertInGroup(input.B, 'server public value');
  const k = await multiplierK();
  const u = await scramblingParameter(input.ephemeral.A, B);

  const kv = (k * computeVerifier(input.x)) % SRP_N;
  const base = (((B - kv) % SRP_N) + SRP_N) % SRP_N;
  const S = modPow(base, input.ephemeral.a + u * input.x, SRP_N);

  const { M1, M2, sessionKey } = await proofs({
    userId: input.userId,
    salt: input.salt,
    A: input.ephemeral.A,
    B,
    S,
  });
  return { M1, expectedM2: M2, sessionKey };
}

export function verifyServerProof(session: ClientSession, M2: Uint8Array): void {
  if (!constantTimeEqual(session.expectedM2, M2)) throw new SrpError('server proof mismatch');
}

export interface ServerSession {
  readonly M2: Uint8Array;
  readonly sessionKey: Uint8Array;
}

/**
 * Verify the client's proof. Returns null on mismatch rather than throwing, so
 * the caller reports one generic failure for every reason a handshake can fail
 * and never leaks which step went wrong.
 */
export async function verifyClientSession(input: {
  readonly userId: string;
  readonly salt: Uint8Array;
  readonly verifier: bigint;
  readonly ephemeral: ServerEphemeral;
  readonly A: bigint;
  readonly M1: Uint8Array;
}): Promise<ServerSession | null> {
  const A = assertInGroup(input.A, 'client public value');
  const u = await scramblingParameter(A, input.ephemeral.B);

  const base = (A * modPow(input.verifier, u, SRP_N)) % SRP_N;
  const S = modPow(base, input.ephemeral.b, SRP_N);

  const { M1, M2, sessionKey } = await proofs({
    userId: input.userId,
    salt: input.salt,
    A,
    B: input.ephemeral.B,
    S,
  });
  if (!constantTimeEqual(M1, input.M1)) return null;
  return { M2, sessionKey };
}
