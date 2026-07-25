import { bytesToBigInt, modPow } from '../src/bigint';
import { randomBytes, toBase64 } from '../src/bytes';
import {
  computeClientSession,
  computeVerifier,
  createClientEphemeral,
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  SRP_ELEMENT_BYTES,
  SRP_G,
  SRP_N,
  SrpError,
  srpPrivateKey,
  verifyClientSession,
  verifyServerProof,
} from '../src/srp';

const USER_ID = 'a4d1b0c2-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
const SALT = Uint8Array.from({ length: 16 }, (_, i) => i * 3 + 5);

function privateKey(seed: number): bigint {
  return srpPrivateKey(Uint8Array.from({ length: 32 }, (_, i) => (i * seed + 11) % 251));
}

/** One full handshake, both roles, as the service and the client run it. */
async function handshake(options: {
  clientX?: bigint;
  serverX?: bigint;
  tamperA?: (a: bigint) => bigint;
  tamperB?: (b: bigint) => bigint;
}): Promise<{ accepted: boolean; clientVerifiedServer: boolean }> {
  const clientX = options.clientX ?? privateKey(3);
  const serverX = options.serverX ?? clientX;
  const verifier = computeVerifier(serverX);

  const serverEphemeral = await createServerEphemeral(verifier);
  const clientEphemeral = createClientEphemeral();

  const session = await computeClientSession({
    userId: USER_ID,
    salt: SALT,
    x: clientX,
    ephemeral: clientEphemeral,
    B: options.tamperB ? options.tamperB(serverEphemeral.B) : serverEphemeral.B,
  });

  const result = await verifyClientSession({
    userId: USER_ID,
    salt: SALT,
    verifier,
    ephemeral: serverEphemeral,
    A: options.tamperA ? options.tamperA(clientEphemeral.A) : clientEphemeral.A,
    M1: session.M1,
  });

  if (!result) return { accepted: false, clientVerifiedServer: false };
  try {
    verifyServerProof(session, result.M2);
    // Both sides must have landed on the same session key, or nothing derived
    // from it (the keyset-auth key) would agree later.
    expect(Buffer.from(result.sessionKey)).toEqual(Buffer.from(session.sessionKey));
    return { accepted: true, clientVerifiedServer: true };
  } catch {
    return { accepted: true, clientVerifiedServer: false };
  }
}

describe('SRP group constant', () => {
  it('is the 4096-bit RFC 5054 group with g = 5', () => {
    expect(SRP_N.toString(2).length).toBe(4096);
    expect(SRP_G).toBe(5n);
    // Safe-prime MODP groups from RFC 3526 start and end with 64 set bits.
    expect(SRP_N >> 4032n).toBe((1n << 64n) - 1n);
    expect(SRP_N & ((1n << 64n) - 1n)).toBe((1n << 64n) - 1n);
    expect(SRP_N % 2n).toBe(1n);
  });

  it('passes Fermat tests, so a transcription slip fails the build', () => {
    // Not a proof of primality, but it catches the failure mode that actually
    // threatens a hand-copied constant: a wrong digit.
    for (const base of [2n, 3n, 5n, 7n]) {
      expect(modPow(base, SRP_N - 1n, SRP_N)).toBe(1n);
    }
  });

  it('has (N-1)/2 passing a Fermat test too (safe prime)', () => {
    const q = (SRP_N - 1n) / 2n;
    expect(modPow(2n, q - 1n, q)).toBe(1n);
  });
});

describe('group element encoding', () => {
  it('round-trips through the padded wire form', () => {
    const value = computeVerifier(privateKey(9));
    const encoded = encodeGroupElement(value);
    expect(Buffer.from(encoded, 'base64')).toHaveLength(SRP_ELEMENT_BYTES);
    expect(decodeGroupElement(encoded, 'test')).toBe(value);
  });

  it.each([
    ['zero', 0n],
    ['N itself', SRP_N],
  ])('rejects %s', (_label, value) => {
    const encoded = toBase64(
      Uint8Array.from(Buffer.from(value.toString(16).padStart(1024, '0'), 'hex')),
    );
    expect(() => decodeGroupElement(encoded, 'test')).toThrow(SrpError);
  });

  it('rejects a wrongly sized element', () => {
    expect(() => decodeGroupElement(toBase64(randomBytes(32)), 'test')).toThrow(SrpError);
  });
});

describe('srpPrivateKey', () => {
  it('rejects a degenerate private key', () => {
    expect(() => srpPrivateKey(new Uint8Array(32))).toThrow(SrpError);
  });

  it('reduces the 2SKD output into the group', () => {
    const bytes = randomBytes(32);
    expect(srpPrivateKey(bytes)).toBe(bytesToBigInt(bytes) % SRP_N);
  });
});

describe('SRP-6a handshake', () => {
  it('succeeds and agrees on a session key when the password matches', async () => {
    await expect(handshake({})).resolves.toEqual({ accepted: true, clientVerifiedServer: true });
  });

  it('produces a different A on every run', () => {
    const first = createClientEphemeral();
    const second = createClientEphemeral();
    expect(first.A).not.toBe(second.A);
  });

  it('rejects a wrong password', async () => {
    const result = await handshake({ clientX: privateKey(3), serverX: privateKey(4) });
    expect(result.accepted).toBe(false);
  });

  it('rejects a tampered client public value', async () => {
    const result = await handshake({ tamperA: (a) => (a + 1n) % SRP_N });
    expect(result.accepted).toBe(false);
  });

  it('detects a server that cannot prove it holds the verifier', async () => {
    // The client still computes a proof against a substituted B, but the
    // server's M2 will not match - which is what stops a fake server from
    // collecting a wrapped master key request.
    const result = await handshake({ tamperB: (b) => (b + 1n) % SRP_N });
    expect(result.clientVerifiedServer).toBe(false);
  });

  it.each([
    ['zero', 0n],
    ['N', SRP_N],
    ['a multiple of N', SRP_N * 2n],
  ])('refuses a reflected client value of %s', async (_label, value) => {
    const verifier = computeVerifier(privateKey(3));
    const serverEphemeral = await createServerEphemeral(verifier);
    await expect(
      verifyClientSession({
        userId: USER_ID,
        salt: SALT,
        verifier,
        ephemeral: serverEphemeral,
        A: value,
        M1: new Uint8Array(32),
      }),
    ).rejects.toThrow(SrpError);
  });

  it.each([
    ['zero', 0n],
    ['N', SRP_N],
  ])('refuses a server value of %s on the client', async (_label, value) => {
    await expect(
      computeClientSession({
        userId: USER_ID,
        salt: SALT,
        x: privateKey(3),
        ephemeral: createClientEphemeral(),
        B: value,
      }),
    ).rejects.toThrow(SrpError);
  });

  it('binds the proof to the user identity', async () => {
    const x = privateKey(3);
    const verifier = computeVerifier(x);
    const serverEphemeral = await createServerEphemeral(verifier);
    const clientEphemeral = createClientEphemeral();
    const session = await computeClientSession({
      userId: USER_ID,
      salt: SALT,
      x,
      ephemeral: clientEphemeral,
      B: serverEphemeral.B,
    });

    const wrongIdentity = await verifyClientSession({
      userId: '00000000-0000-4000-8000-000000000000',
      salt: SALT,
      verifier,
      ephemeral: serverEphemeral,
      A: clientEphemeral.A,
      M1: session.M1,
    });
    expect(wrongIdentity).toBeNull();
  });

  it('binds the proof to the salt', async () => {
    const x = privateKey(3);
    const verifier = computeVerifier(x);
    const serverEphemeral = await createServerEphemeral(verifier);
    const clientEphemeral = createClientEphemeral();
    const session = await computeClientSession({
      userId: USER_ID,
      salt: SALT,
      x,
      ephemeral: clientEphemeral,
      B: serverEphemeral.B,
    });

    const wrongSalt = await verifyClientSession({
      userId: USER_ID,
      salt: new Uint8Array(16),
      verifier,
      ephemeral: serverEphemeral,
      A: clientEphemeral.A,
      M1: session.M1,
    });
    expect(wrongSalt).toBeNull();
  });

  it('never lets a verifier alone impersonate the client', async () => {
    // The server-side material is not enough to produce a client proof: that is
    // the property that makes a stolen vault database useless.
    const x = privateKey(3);
    const verifier = computeVerifier(x);
    const serverEphemeral = await createServerEphemeral(verifier);
    const attackerEphemeral = createClientEphemeral();

    const attackerSession = await computeClientSession({
      userId: USER_ID,
      salt: SALT,
      x: srpPrivateKey(Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0))),
      ephemeral: attackerEphemeral,
      B: serverEphemeral.B,
    });

    const result = await verifyClientSession({
      userId: USER_ID,
      salt: SALT,
      verifier,
      ephemeral: serverEphemeral,
      A: attackerEphemeral.A,
      M1: attackerSession.M1,
    });
    expect(result).toBeNull();
  });
});
