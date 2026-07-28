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
  expectedEnvVarFor,
  inboundCredentialFor,
  outboundCredentialsFor,
  SERVICE_CREDENTIAL_GRAPH,
} from '../src/credential-graph';

const IDENTITY = 'IDENTITY_INTERNAL_TOKEN';
const SETTLEMENT = 'SETTLEMENT_INTERNAL_TOKEN';

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
  it('derives the mandated variable name from the service', () => {
    expect(expectedEnvVarFor('identity')).toBe(IDENTITY);
    expect(expectedEnvVarFor('documents')).toBe('DOCUMENTS_INTERNAL_TOKEN');
  });

  it('resolves inbound credentials, and none for services without internal routes', () => {
    expect(inboundCredentialFor('identity')?.envVar).toBe(IDENTITY);
    expect(inboundCredentialFor('vault')).toBeUndefined();
    expect(inboundCredentialFor('audit')).toBeUndefined();
  });

  it('resolves outbound credentials by holder', () => {
    expect(outboundCredentialsFor('vault').map((e) => e.envVar)).toEqual([SETTLEMENT]);
    expect(outboundCredentialsFor('settlement').map((e) => e.envVar)).toEqual([IDENTITY]);
    expect(outboundCredentialsFor('profile')).toEqual([]);
  });

  it('grants settlement both directions, and never the same variable twice', () => {
    // Settlement is the only service with two credentials — the shape that
    // collapsed in M7. Its inbound and outbound must be different variables.
    const granted = credentialEnvVarsFor('settlement');
    expect(granted).toEqual([IDENTITY, SETTLEMENT].sort());
    expect(new Set(granted).size).toBe(granted.length);
    expect(inboundCredentialFor('settlement')?.envVar).not.toBe(
      outboundCredentialsFor('settlement')[0]?.envVar,
    );
  });

  it('grants nothing to services with no service-to-service reach', () => {
    for (const service of ['profile', 'assets', 'plaid', 'audit'] as const) {
      expect(credentialEnvVarsFor(service)).toEqual([]);
    }
  });

  it('grants documents its own inbound credential and no outbound one', () => {
    expect(credentialEnvVarsFor('documents')).toEqual(['DOCUMENTS_INTERNAL_TOKEN']);
    expect(outboundCredentialsFor('documents')).toEqual([]);
  });
});
