/**
 * `credentialsHeldIn` is the detector every service's config spec trusts to
 * answer "which secrets did I just absorb?". If it under-reports, all eight of
 * those assertions pass vacuously and the graph is enforced in name only — so
 * its blind spots are tested here directly, not inferred from the fact that the
 * services are green.
 */
import {
  credentialEnvVarsFor,
  credentialSentinel,
  credentialSentinelEnv,
  credentialsHeldIn,
  envVarPrefixFor,
  inboundCredentialsFor,
  outboundCredentialsFor,
  SERVICE_CREDENTIAL_GRAPH,
} from '../src/credential-graph';

const IDENTITY = 'IDENTITY_INTERNAL_TOKEN';
const SETTLEMENT = 'SETTLEMENT_INTERNAL_TOKEN';
const NOTIFICATIONS = 'NOTIFICATIONS_INTERNAL_TOKEN';
const NOTIFICATIONS_RECIPIENTS = 'NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN';
const NOTIFICATIONS_VERIFY = 'NOTIFICATIONS_VERIFY_INTERNAL_TOKEN';
const NOTIFICATIONS_STATUS = 'NOTIFICATIONS_STATUS_INTERNAL_TOKEN';
const NOTIFICATIONS_SECURITY = 'NOTIFICATIONS_SECURITY_INTERNAL_TOKEN';
const NOTIFICATIONS_RECOVERY = 'NOTIFICATIONS_RECOVERY_INTERNAL_TOKEN';

describe('credentialsHeldIn', () => {
  it('reports nothing for a config that holds no credential', () => {
    expect(credentialsHeldIn({ databaseUrl: 'postgres://x/y', port: 3006 })).toEqual([]);
  });

  it('finds a credential in a plain top-level field', () => {
    expect(credentialsHeldIn({ token: credentialSentinel(IDENTITY) })).toEqual([IDENTITY]);
  });

  it('finds a credential NESTED inside a port config', () => {
    // The shape this repo already uses for kms/objectStore/scanner/ocr. A
    // top-level-only sweep would miss it, and folding a credential into a
    // nested options object is the most natural way to hide one by accident.
    const config = { lock: { url: 'https://identity', credential: credentialSentinel(IDENTITY) } };
    expect(credentialsHeldIn(config)).toEqual([IDENTITY]);
  });

  it('finds a credential inside an array', () => {
    expect(credentialsHeldIn({ peers: [{ secret: credentialSentinel(SETTLEMENT) }] })).toEqual([
      SETTLEMENT,
    ]);
  });

  it('finds a credential stored as a Buffer', () => {
    // Several configs hold Buffers (emailIndexKey, searchIndexKey, kms.masterKey);
    // a credential coerced into one must not vanish from the report.
    const config = { blob: Buffer.from(credentialSentinel(SETTLEMENT), 'utf8') };
    expect(credentialsHeldIn(config)).toEqual([SETTLEMENT]);
  });

  it('finds a credential embedded in a larger composed string', () => {
    const config = { url: `https://svc/?k=${credentialSentinel(IDENTITY)}#frag` };
    expect(credentialsHeldIn(config)).toEqual([IDENTITY]);
  });

  it('reports every distinct credential once, sorted', () => {
    const config = {
      a: credentialSentinel(SETTLEMENT),
      b: { c: credentialSentinel(IDENTITY) },
      d: credentialSentinel(IDENTITY),
    };
    expect(credentialsHeldIn(config)).toEqual([IDENTITY, SETTLEMENT].sort());
  });

  it('survives cycles and exotic values instead of hanging', () => {
    const cyclic: Record<string, unknown> = { token: credentialSentinel(IDENTITY) };
    cyclic['self'] = cyclic;
    cyclic['nothing'] = null;
    cyclic['count'] = 7;
    cyclic['flag'] = true;
    cyclic['missing'] = undefined;
    expect(credentialsHeldIn(cyclic)).toEqual([IDENTITY]);
  });

  it('ignores a value that merely resembles a sentinel', () => {
    expect(
      credentialsHeldIn({ token: 'credential-graph-sentinel::NOPE::not-a-real-secret' }),
    ).toEqual([]);
  });
});

describe('the sentinel fixture', () => {
  it('covers every credential in the graph', () => {
    const env = credentialSentinelEnv();
    expect(Object.keys(env).sort()).toEqual(
      SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.envVar).sort(),
    );
    for (const [envVar, value] of Object.entries(env)) {
      // Long enough to satisfy the >= 32 char production rules, so one fixture
      // works in either NODE_ENV, and self-identifying so the value found in a
      // config says which variable produced it.
      expect(value.length).toBeGreaterThanOrEqual(32);
      expect(value).toContain(envVar);
    }
  });

  it('round-trips through the detector', () => {
    // The end-to-end property the services rely on: everything in the fixture
    // is findable, so a missing report means the service really did not take it.
    expect(credentialsHeldIn(credentialSentinelEnv())).toEqual(
      SERVICE_CREDENTIAL_GRAPH.map((edge) => edge.envVar).sort(),
    );
  });
});

describe('graph lookup helpers', () => {
  it('derives the mandated name prefix from the service', () => {
    expect(envVarPrefixFor('identity')).toBe('IDENTITY_');
    expect(envVarPrefixFor('documents')).toBe('DOCUMENTS_');
  });

  it('resolves inbound credentials, and none for services without internal routes', () => {
    expect(inboundCredentialsFor('identity').map((e) => e.envVar)).toEqual([IDENTITY]);
    expect(inboundCredentialsFor('vault')).toEqual([]);
    expect(inboundCredentialsFor('audit')).toEqual([]);
  });

  it('gives notifications SIX inbound credentials, one per capability (M9 review, M14, M17)', () => {
    // The send surface and the recipient-upsert surface have different
    // legitimate holders, so they must not share a secret: holding "may
    // notify this user" must not also mean "may decide where their alerts go".
    const inbound = inboundCredentialsFor('notifications');
    expect(inbound.map((e) => e.envVar)).toEqual([
      NOTIFICATIONS,
      NOTIFICATIONS_RECIPIENTS,
      NOTIFICATIONS_VERIFY,
      NOTIFICATIONS_SECURITY,
      NOTIFICATIONS_RECOVERY,
      NOTIFICATIONS_STATUS,
    ]);
    // M13 added profile: it tells an owner when somebody CLAIMED a link to one
    // of their contacts. Send-only, like the other two — profile has no business
    // deciding where anybody's notifications go.
    expect(inbound.find((e) => e.envVar === NOTIFICATIONS)?.holders).toEqual([
      'profile',
      'settlement',
      'vault',
    ]);
    // The load-bearing half: identity, and nobody else, may repoint an address
    // or vouch for one.
    expect(inbound.find((e) => e.envVar === NOTIFICATIONS_RECIPIENTS)?.holders).toEqual([
      'identity',
    ]);
    // M14. Mailing a verification code is identity's alone and is NOT the send
    // credential — the service that mints sessions must not be able to fire
    // "a death report was filed on your account".
    expect(inbound.find((e) => e.envVar === NOTIFICATIONS_VERIFY)?.holders).toEqual(['identity']);
    // M14. Reading the verified bit is a read of DELIVERY STATE, which the send
    // edge promises not to expose; settlement sends and never asks, so it is
    // deliberately absent here. Vault and profile join in PR2, in the same
    // change as the clients that present it.
    // M14 PR2 added vault and profile, in the same change as the clients that
    // present it. SETTLEMENT is still absent, and that absence is the gate
    // classification made structural: its §5.1 gates PROCEED on an unverified
    // recipient and record the fact, so it never asks the question — and a
    // service that never asks must not hold the key to it.
    expect(inbound.find((e) => e.envVar === NOTIFICATIONS_STATUS)?.holders).toEqual([
      'identity',
      'profile',
      'vault',
    ]);
    expect(inbound.find((e) => e.envVar === NOTIFICATIONS_STATUS)?.holders).not.toContain(
      'settlement',
    );
    // ...and each is enforced by its OWN guard, or the split is cosmetic: a
    // guard binds exactly one token, so the token IS the partition.
    //
    // DERIVED from the inbound list rather than asserted as a literal, because
    // the security property is "one guard per credential" and not the number —
    // a hardcoded count goes stale on the next edge and says nothing extra
    // while it is right. The floor keeps it from passing vacuously if the
    // lookup ever returns nothing.
    expect(inbound.length).toBeGreaterThanOrEqual(4);
    expect(new Set(inbound.map((e) => e.guard.token)).size).toBe(inbound.length);
  });

  it('resolves outbound credentials by holder', () => {
    expect(outboundCredentialsFor('vault').map((e) => e.envVar)).toEqual([
      SETTLEMENT,
      NOTIFICATIONS,
      // M14: the STATUS read for the escrow-arming gates.
      NOTIFICATIONS_STATUS,
    ]);
    expect(outboundCredentialsFor('settlement').map((e) => e.envVar)).toEqual([
      IDENTITY,
      'DOCUMENTS_INTERNAL_TOKEN',
      NOTIFICATIONS,
    ]);
    // Identity holds FIVE notifications credentials and NOT the send one: it
    // feeds the store, mails its own verification code, announces a change to
    // the account's own credentials (M17), and reads the verified bit — but can
    // never fire an ESTATE notification. That last clause is the one worth
    // asserting by name below: gaining the ability to say "your password
    // changed" must not come with the ability to say "a death report was filed
    // on your account".
    expect(outboundCredentialsFor('identity').map((e) => e.envVar)).toEqual([
      NOTIFICATIONS_RECIPIENTS,
      NOTIFICATIONS_VERIFY,
      NOTIFICATIONS_SECURITY,
      NOTIFICATIONS_RECOVERY,
      NOTIFICATIONS_STATUS,
    ]);
    expect(outboundCredentialsFor('identity').map((e) => e.envVar)).not.toContain(NOTIFICATIONS);
    // M13 gave profile its first outbound credential; M14 added the STATUS read
    // for the link-code MINT gate. Still no recipients credential: profile can
    // ask whether an owner proved their address, never set or vouch for one.
    expect(outboundCredentialsFor('profile').map((e) => e.envVar)).toEqual([
      NOTIFICATIONS,
      NOTIFICATIONS_STATUS,
    ]);
    expect(outboundCredentialsFor('profile').map((e) => e.envVar)).not.toContain(
      NOTIFICATIONS_RECIPIENTS,
    );
  });

  it('grants settlement four distinct variables, never the same one twice', () => {
    // Settlement now touches four credentials — its own inbound plus three
    // outbound (identity account-lock, M9 notifications SEND, M9 PR2 documents
    // legal hold). Pairwise distinct is the shape whose collapse the M7
    // review found.
    const granted = credentialEnvVarsFor('settlement');
    expect(granted).toEqual(
      [IDENTITY, NOTIFICATIONS, SETTLEMENT, 'DOCUMENTS_INTERNAL_TOKEN'].sort(),
    );
    expect(new Set(granted).size).toBe(granted.length);
    const inboundVars = inboundCredentialsFor('settlement').map((e) => e.envVar);
    for (const outbound of outboundCredentialsFor('settlement')) {
      expect(inboundVars).not.toContain(outbound.envVar);
    }
  });

  it('grants nothing to services with no service-to-service reach', () => {
    // Profile left this list in M13 when it gained the notifications SEND
    // credential — and gained nothing else: it holds no inbound credential, so
    // no peer can address it with anything but a user's own bearer.
    for (const service of ['assets', 'plaid', 'audit'] as const) {
      expect(credentialEnvVarsFor(service)).toEqual([]);
    }
    expect(credentialEnvVarsFor('profile')).toEqual([NOTIFICATIONS, NOTIFICATIONS_STATUS]);
    // Still no INBOUND credential — the property this test is named for. M14
    // widened what profile may PRESENT; it did not make profile addressable by
    // a peer with anything but a user's own bearer.
    expect(inboundCredentialsFor('profile')).toEqual([]);
  });

  it('grants documents its own inbound credential and no outbound one', () => {
    expect(credentialEnvVarsFor('documents')).toEqual(['DOCUMENTS_INTERNAL_TOKEN']);
    expect(outboundCredentialsFor('documents')).toEqual([]);
  });
});
