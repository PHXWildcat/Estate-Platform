/**
 * @jest-environment jsdom
 */

/**
 * EMERGENCY ACCESS, END TO END, WITH REAL CRYPTO ON BOTH SIDES (M15 PR3).
 *
 * The owner splits their recovery key on their device; a grantee, days later,
 * reconstructs it on theirs. Everything in between is a server that stores
 * opaque values and — asserted here rather than argued — holds no part of the
 * master key it is escrowing.
 *
 * This is the milestone's central Zone A claim for emergency access, so the
 * test drives the real `@estate/vault-crypto` primitives through the real
 * client module. A stubbed crypto layer here would prove only that the calls
 * happen in the right order.
 */
import {
  createVaultEnrollment,
  exportMasterKeyBytes,
  fromBase64,
  generateRecoveryKeyPair,
  MIN_ITERATIONS,
  prepareUnlock,
  publicKeyFingerprint,
  toBase64,
} from '@estate/vault-crypto';
import {
  configureEscrow,
  granteeCandidates,
  offerFor,
  ownRecoveryKey,
  publishRecoveryKey,
  releaseAndRecover,
  type GranteeCandidate,
} from '../src/client/emergency';

const OWNER = '11111111-2222-4333-8444-555555555555';
const GRANTEE = '22222222-3333-4444-8555-666666666666';

/**
 * A server that keeps exactly what the real one keeps, and nothing else.
 *
 * Everything it is handed is recorded, so the test can afterwards go looking
 * for the master key in it and fail to find it.
 */
interface Server {
  /** Whose device is talking right now. The real edge knows this from a cookie. */
  caller: string;
  recoveryKeys: Map<string, { publicKey: string; wrappedPrivateKey: string }>;
  escrow: {
    platformPart: string;
    wrappedMasterKeyRecovery: string;
    threshold: number;
    grantees: Array<Record<string, unknown>>;
  } | null;
  candidates: GranteeCandidate[];
  /** Every request body, verbatim. */
  bodies: string[];
  releases: number;
}

function installServer(): Server {
  const state: Server = {
    caller: OWNER,
    recoveryKeys: new Map(),
    escrow: null,
    candidates: [],
    bodies: [],
    releases: 0,
  };

  const reply = (status: number, payload: unknown): unknown => ({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  });

  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET';
    const body = typeof init.body === 'string' ? init.body : '';
    if (body) state.bodies.push(body);
    const parsed = body ? (JSON.parse(body) as Record<string, unknown>) : {};

    if (path === '/api/grantee-candidates') {
      return Promise.resolve(reply(200, { candidates: state.candidates }));
    }
    if (path === '/api/vault/recovery-key' && method === 'POST') {
      state.recoveryKeys.set(state.caller, {
        publicKey: parsed['publicKey'] as string,
        wrappedPrivateKey: parsed['wrappedPrivateKey'] as string,
      });
      return Promise.resolve(reply(201, { status: 'ok' }));
    }
    if (path === '/api/vault/recovery-key' && method === 'GET') {
      const own = state.recoveryKeys.get(state.caller);
      return Promise.resolve(
        own ? reply(200, own) : reply(404, { error: 'recovery_key_not_found' }),
      );
    }
    if (path.startsWith('/api/vault/recovery-key/')) {
      // The PUBLIC half only. The service never serves anyone else's wrapped
      // private key, which is what makes a release need the grantee's own vault.
      const target = path.split('/').pop() as string;
      const found = state.recoveryKeys.get(target);
      return Promise.resolve(
        found
          ? reply(200, { granteeUserId: target, publicKey: found.publicKey })
          : reply(404, { error: 'recovery_key_not_found' }),
      );
    }
    if (path === '/api/vault/emergency-access' && method === 'POST') {
      state.escrow = {
        platformPart: parsed['platformPart'] as string,
        wrappedMasterKeyRecovery: parsed['wrappedMasterKeyRecovery'] as string,
        threshold: parsed['threshold'] as number,
        grantees: parsed['grantees'] as Array<Record<string, unknown>>,
      };
      return Promise.resolve(reply(201, { configured: true, threshold: 1, policies: [] }));
    }
    if (path.endsWith('/release')) {
      // Handing over the platform half is what SPENDS the escrow, which is why
      // the real service allows it exactly once.
      if (!state.escrow || state.releases > 0) {
        return Promise.resolve(reply(409, { error: 'already_released' }));
      }
      state.releases += 1;
      const share = state.escrow.grantees[0] as Record<string, unknown>;
      return Promise.resolve(
        reply(200, {
          ownerUserId: OWNER,
          platformPart: state.escrow.platformPart,
          wrappedMasterKeyRecovery: state.escrow.wrappedMasterKeyRecovery,
          keyShare: share['keyShare'],
          threshold: state.escrow.threshold,
        }),
      );
    }
    return Promise.resolve(reply(200, {}));
  }) as unknown as typeof fetch;

  return state;
}

/** Enrol one vault for real, and hand back the master key in both shapes. */
async function enrol(userId: string): Promise<{ key: CryptoKey; bytes: Uint8Array }> {
  const { enrollment, masterKey } = await createVaultEnrollment({
    userId,
    password: `${userId} vault password`,
    iterations: MIN_ITERATIONS,
  });
  const prepared = await prepareUnlock({
    userId,
    password: `${userId} vault password`,
    secretKey: enrollment.secretKey,
    kdfParams: enrollment.payload.kdfParams,
    srpSalt: enrollment.payload.srpSalt,
  });
  // The BYTES are what `createEscrow` splits; the KEY is what wraps the
  // recovery private half. Both are the same secret, and the round trip below
  // asserts the reconstruction against the bytes.
  const bytes = await exportMasterKeyBytes({
    userId,
    auk: prepared.auk,
    wrappedMasterKey: enrollment.payload.wrappedMasterKey,
  });
  return { key: masterKey, bytes };
}

jest.setTimeout(180_000);

describe('emergency access, owner device to grantee device', () => {
  let server: Server;
  let owner: { key: CryptoKey; bytes: Uint8Array };
  let grantee: { key: CryptoKey; bytes: Uint8Array };

  beforeAll(async () => {
    owner = await enrol(OWNER);
    grantee = await enrol(GRANTEE);
  });

  beforeEach(() => {
    server = installServer();
    server.candidates = [{ contactId: 'contact-1', userId: GRANTEE, name: 'Ada' }];
  });

  it('reconstructs exactly the owner’s master key, through a server holding no part of it', async () => {
    // 1. The grantee publishes a recovery key. Until this exists nobody can be
    //    named — there is no key to seal a share to.
    server.caller = GRANTEE;
    expect((await publishRecoveryKey(GRANTEE, grantee.key)).ok).toBe(true);

    // 2. The owner picks them and confirms the fingerprint out of band.
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const offer = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!offer.ok) throw new Error('offer');
    // 80 bits in the M6-widened alphabet: what the owner reads down a phone.
    expect(offer.data.fingerprint).toMatch(/^[0-9A-HJKMNP-TV-Z-]+$/);
    expect(offer.data.fingerprint.replace(/-/g, '')).toHaveLength(16);
    /*
     * NOT `toBe(await publicKeyFingerprint(offer.data.publicKey))`, which is
     * what this asserted until the M15 review: both sides compute over the SAME
     * served key, so it reduces to f(x) === f(x) and would hold just as well for
     * a key the server had substituted — i.e. it could not fail in the one case
     * the ceremony exists for. What it must show is that the value the OWNER
     * reads out identifies the key the GRANTEE'S DEVICE actually holds, and
     * that a substitution changes it.
     */
    const published = server.recoveryKeys.get(GRANTEE)?.publicKey ?? '';
    expect(offer.data.fingerprint).toBe(await publicKeyFingerprint(fromBase64(published)));

    // 3. Arm. The split happens here, on the owner's device.
    const armed = await configureEscrow({
      ownerUserId: OWNER,
      masterKeyBytes: owner.bytes,
      confirmed: [offer.data],
      threshold: 1,
      waitingPeriodHours: 48,
    });
    expect(armed.ok).toBe(true);
    expect(server.escrow?.grantees).toHaveLength(1);

    // 4. Days later, on the grantee's device, with the grantee's own vault open.
    server.caller = GRANTEE;
    const own = await ownRecoveryKey('grantee-vault-session');
    if (!own.ok) throw new Error('own key');
    const recovered = await releaseAndRecover({
      policyId: 'policy-1',
      granteeUserId: GRANTEE,
      granteeMasterKey: grantee.key,
      granteePublicKey: own.data.publicKey,
      wrappedPrivateKey: own.data.wrappedPrivateKey,
    });
    if (!recovered.ok) throw new Error(`release refused: ${recovered.code}`);

    // THE CLAIM. Not "a key" — the owner's key, byte for byte. The zero check
    // is not decoration: `createEscrow` wipes intermediates, and a comparison
    // of two wiped buffers would pass while proving nothing.
    expect(Buffer.from(owner.bytes).equals(Buffer.alloc(owner.bytes.length))).toBe(false);
    expect(Buffer.from(recovered.data.masterKeyBytes)).toEqual(Buffer.from(owner.bytes));
    expect(recovered.data.ownerUserId).toBe(OWNER);
  });

  it('a SUBSTITUTED grantee key changes the fingerprint the owner reads out', async () => {
    /*
     * The attack the ceremony is the only defence against, and the reason the
     * assertion above cannot be `f(served) === f(served)`: a malicious server
     * serves its OWN public key in place of the grantee's, then — already
     * holding `platform_part` and the recovery-wrapped master key — reads the
     * whole escrow. `grantee_public_key_sha256` cannot catch it, because it is
     * derived client-side from whatever key the client was handed.
     *
     * Nothing detects this except a human comparing two short strings, so the
     * property under test is that the two strings DIFFER when the key does.
     */
    server.caller = GRANTEE;
    await publishRecoveryKey(GRANTEE, grantee.key);
    const honest = server.recoveryKeys.get(GRANTEE);
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const before = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!before.ok) throw new Error('offer');

    const impostor = await generateRecoveryKeyPair();
    server.recoveryKeys.set(GRANTEE, {
      publicKey: toBase64(impostor.publicKey),
      wrappedPrivateKey: honest?.wrappedPrivateKey ?? '',
    });
    const after = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!after.ok) throw new Error('substituted offer');

    expect(after.data.fingerprint).not.toBe(before.data.fingerprint);
    expect(after.data.fingerprint).toBe(await publicKeyFingerprint(impostor.publicKey));
  });

  it('never puts the master key, or anything that opens it, on the wire', async () => {
    server.caller = GRANTEE;
    await publishRecoveryKey(GRANTEE, grantee.key);
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const offer = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!offer.ok) throw new Error('offer');
    await configureEscrow({
      ownerUserId: OWNER,
      masterKeyBytes: owner.bytes,
      confirmed: [offer.data],
      threshold: 1,
      waitingPeriodHours: 48,
    });

    // The master key in every encoding anyone would reach for.
    const wire = server.bodies.join('\n');
    expect(wire).not.toContain(Buffer.from(owner.bytes).toString('base64'));
    expect(wire).not.toContain(Buffer.from(owner.bytes).toString('base64url'));
    expect(wire).not.toContain(Buffer.from(owner.bytes).toString('hex'));
    expect(wire).not.toContain(Buffer.from(grantee.bytes).toString('base64'));

    // And the platform half is a one-time pad against the contacts half: on its
    // own it is indistinguishable from noise, so the wrapped master key the
    // server also holds stays shut. Asserting the LENGTH rather than the value
    // is the honest version of that — there is nothing here to compare it to.
    expect(fromBase64(server.escrow?.platformPart as string)).toHaveLength(32);
  });

  it('refuses to arm with a threshold nobody could ever meet', async () => {
    server.caller = GRANTEE;
    await publishRecoveryKey(GRANTEE, grantee.key);
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const offer = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!offer.ok) throw new Error('offer');

    // 2-of-1 would arm an escrow that can never be opened — the owner would
    // believe they had arranged something and their grantees would find they
    // had not. Refused on the device, before anything is stored.
    await expect(
      configureEscrow({
        ownerUserId: OWNER,
        masterKeyBytes: owner.bytes,
        confirmed: [offer.data],
        threshold: 2,
        waitingPeriodHours: 48,
      }),
    ).rejects.toThrow(/threshold/);
    expect(server.escrow).toBeNull();
  });

  it('will not seal a share to a candidate who has published nothing', async () => {
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const offer = await offerFor(candidates.data[0] as GranteeCandidate);
    expect(offer.ok).toBe(false);
    if (offer.ok) throw new Error('unreachable');
    expect(offer.code).toBe('NOT_FOUND');
  });

  it('is ONE-SHOT: a second release finds the escrow spent', async () => {
    server.caller = GRANTEE;
    await publishRecoveryKey(GRANTEE, grantee.key);
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const offer = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!offer.ok) throw new Error('offer');
    await configureEscrow({
      ownerUserId: OWNER,
      masterKeyBytes: owner.bytes,
      confirmed: [offer.data],
      threshold: 1,
      waitingPeriodHours: 48,
    });

    server.caller = GRANTEE;
    const own = await ownRecoveryKey('grantee-vault-session');
    if (!own.ok) throw new Error('own key');
    const args = {
      policyId: 'policy-1',
      granteeUserId: GRANTEE,
      granteeMasterKey: grantee.key,
      granteePublicKey: own.data.publicKey,
      wrappedPrivateKey: own.data.wrappedPrivateKey,
    };
    expect((await releaseAndRecover(args)).ok).toBe(true);
    const second = await releaseAndRecover(args);
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error('unreachable');
    expect(second.code).toBe('CONFLICT');
    expect(server.releases).toBe(1);
  });

  it('cannot be completed by a grantee who only holds a session', async () => {
    // The share is sealed to a public key whose private half lives inside the
    // grantee's OWN vault. A stolen session reaches the release route and comes
    // away with ciphertext it cannot open — which is the property that makes
    // emergency access safe to expose at all.
    server.caller = GRANTEE;
    await publishRecoveryKey(GRANTEE, grantee.key);
    server.caller = OWNER;
    const candidates = await granteeCandidates();
    if (!candidates.ok) throw new Error('candidates');
    const offer = await offerFor(candidates.data[0] as GranteeCandidate);
    if (!offer.ok) throw new Error('offer');
    await configureEscrow({
      ownerUserId: OWNER,
      masterKeyBytes: owner.bytes,
      confirmed: [offer.data],
      threshold: 1,
      waitingPeriodHours: 48,
    });

    server.caller = GRANTEE;
    const own = await ownRecoveryKey('grantee-vault-session');
    if (!own.ok) throw new Error('own key');
    // The attacker has everything the wire carries — and the wrong master key.
    await expect(
      releaseAndRecover({
        policyId: 'policy-1',
        granteeUserId: GRANTEE,
        granteeMasterKey: owner.key,
        granteePublicKey: own.data.publicKey,
        wrappedPrivateKey: own.data.wrappedPrivateKey,
      }),
    ).rejects.toThrow();
  });
});
