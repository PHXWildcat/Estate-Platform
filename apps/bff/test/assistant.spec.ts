import type { INestApplication } from '@nestjs/common';
import type { AnalysisView } from '../src/assistant-client';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import { ANALYSIS, ASSET, FakeAssistantClient, TOKENS, gql, gqlBody, makeApp } from './helpers';

/**
 * The assistant resolvers (M10 PR4). Two properties are pinned here and the
 * data mapping is incidental to both.
 *
 * FIRST, THE TOKEN FLOW: the BFF forwards the caller's own bearer, exactly as
 * it does for assets. The assistant holds no credential of its own either, so
 * this is the whole chain from browser to analyser running on one session's
 * authority.
 *
 * SECOND, THE STATUS TAXONOMY: a failed or refused analysis must reach the UI
 * as a status rather than as an empty finding list. "Nothing found" and "could
 * not look" are the two sentences this feature exists to keep apart, and the
 * readiness page renders four analyses at once — so one failure must cost its
 * own card and nothing else.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const READINESS_QUERY = `query Readiness {
  readiness {
    funding { status reason disclaimer findings { code severity subject { kind ref label } detail } }
    missingDocuments { status reason findings { code } }
    beneficiaryConflicts { status reason findings { code } }
    estateTax { status reason findings { code } }
  }
}`;
const CONSENTS_QUERY = 'query Consents { consents }';
const GRANT_MUTATION = 'mutation GrantConsent($scope: String!) { grantConsent(scope: $scope) }';
const REVOKE_MUTATION = 'mutation RevokeConsent($scope: String!) { revokeConsent(scope: $scope) }';

function unavailable(reason: string): AnalysisView {
  return { status: 'UNAVAILABLE', reason, findings: [], disclaimer: ANALYSIS.disclaimer };
}

describe('readiness resolver', () => {
  let app: INestApplication;
  let assistant: FakeAssistantClient;

  beforeEach(async () => {
    assistant = new FakeAssistantClient();
    app = await makeApp({ assistant });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the CALLER’S bearer to every analysis, never anything the BFF minted', async () => {
    const res = await gql(app, { query: READINESS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors).toBeUndefined();
    // Four analyses, one session's authority, and the exact cookie value.
    expect(assistant.analysisCalls.map((call) => call.accessToken)).toEqual([
      TOKENS.accessToken,
      TOKENS.accessToken,
      TOKENS.accessToken,
      TOKENS.accessToken,
    ]);
    expect(assistant.analysisCalls.map((call) => call.name)).toEqual([
      'funding',
      'missing-documents',
      'beneficiary-conflicts',
      'estate-tax',
    ]);
  });

  it('returns findings as structured data, with the watermark on every analysis', async () => {
    const res = await gql(app, { query: READINESS_QUERY }, { cookie: COOKIE });
    const readiness = gqlBody(res).data?.['readiness'] as Record<string, AnalysisView>;
    expect(readiness['funding']).toEqual({
      status: 'OK',
      reason: null,
      disclaimer: ANALYSIS.disclaimer,
      findings: [
        {
          code: 'asset_not_titled_in_trust',
          severity: 'high',
          subject: { kind: 'asset', ref: ASSET.assetId, label: 'The lake house' },
          // Money crosses as a decimal STRING, never a Float.
          detail: { category: 'real_estate', estValue: '250000.00' },
        },
      ],
    });
  });

  it('lets ONE analysis fail without blanking the other three', async () => {
    // The reason the schema carries a status instead of throwing: a peer
    // blinking during one analysis costs that card, not the page.
    assistant.analysisResults.set('estate-tax', unavailable('upstream_unavailable'));
    const res = await gql(app, { query: READINESS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors).toBeUndefined();
    const readiness = gqlBody(res).data?.['readiness'] as Record<string, AnalysisView>;
    expect(readiness['estateTax']).toMatchObject({
      status: 'UNAVAILABLE',
      reason: 'upstream_unavailable',
      findings: [],
    });
    expect(readiness['funding']?.status).toBe('OK');
    expect(readiness['funding']?.findings).toHaveLength(1);
  });

  it('never renders a failure as an empty result', async () => {
    // The invariant that survives every layer: a non-OK status carries no
    // findings, so a client cannot read "we could not look" as "nothing found".
    for (const status of ['UNAVAILABLE', 'REFUSED', 'DISABLED'] as const) {
      assistant.analysisResults.set('funding', {
        status,
        reason: 'reference_unreviewed',
        findings: [],
        disclaimer: ANALYSIS.disclaimer,
      });
      const res = await gql(app, { query: READINESS_QUERY }, { cookie: COOKIE });
      const readiness = gqlBody(res).data?.['readiness'] as Record<string, AnalysisView>;
      expect(readiness['funding']?.status).toBe(status);
      expect(readiness['funding']?.findings).toEqual([]);
      // …and the watermark is still there, because a user being told "we could
      // not compute this" is still being told something about their estate.
      expect(readiness['funding']?.disclaimer).toBe(ANALYSIS.disclaimer);
    }
  });

  it('refuses without a session cookie, before reaching the assistant', async () => {
    const res = await gql(app, { query: READINESS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(assistant.analysisCalls).toEqual([]);
  });

  it('surfaces an expired session as UNAUTHENTICATED, not as four dead cards', async () => {
    // A 401 is a fact about the whole request: the client must re-authenticate
    // rather than read four "unavailable" analyses and retry them forever.
    assistant.analysisError = bffError('UNAUTHENTICATED');
    const res = await gql(app, { query: READINESS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
  });
});

describe('consent resolvers', () => {
  let app: INestApplication;
  let assistant: FakeAssistantClient;

  beforeEach(async () => {
    assistant = new FakeAssistantClient();
    app = await makeApp({ assistant });
  });

  afterEach(async () => {
    await app.close();
  });

  it('reads the caller’s grants on their own bearer', async () => {
    assistant.consentsResult = ['assistant.enabled', 'assistant.assets'];
    const res = await gql(app, { query: CONSENTS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).data?.['consents']).toEqual(['assistant.enabled', 'assistant.assets']);
    expect(assistant.consentsCalls).toEqual([TOKENS.accessToken]);
  });

  it('grants a scope and answers with the full grant set', async () => {
    // The client never has to guess what it now holds — which matters because
    // absence IS denial, so an optimistic local update could show a grant the
    // server refused.
    const res = await gql(
      app,
      { query: GRANT_MUTATION, variables: { scope: 'assistant.assets' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).data?.['grantConsent']).toEqual(['assistant.enabled', 'assistant.assets']);
    expect(assistant.grantCalls).toEqual([
      { accessToken: TOKENS.accessToken, scope: 'assistant.assets' },
    ]);
  });

  it('surfaces the step-up requirement as its own code', async () => {
    // docs/01 §5: granting widens what may reach a third-party model provider,
    // which is export-class. The UI keys its inline TOTP prompt off this code.
    assistant.grantError = bffError('STEPUP_REQUIRED');
    const res = await gql(
      app,
      { query: GRANT_MUTATION, variables: { scope: 'assistant.assets' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('STEPUP_REQUIRED');
  });

  it('revokes without any step-up — the protective action is never harder', async () => {
    assistant.consentsResult = ['assistant.enabled', 'assistant.assets'];
    const res = await gql(
      app,
      { query: REVOKE_MUTATION, variables: { scope: 'assistant.assets' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).data?.['revokeConsent']).toEqual(['assistant.enabled']);
    expect(assistant.revokeCalls).toEqual([
      { accessToken: TOKENS.accessToken, scope: 'assistant.assets' },
    ]);
  });

  it('refuses consent writes without a session', async () => {
    const res = await gql(app, {
      query: GRANT_MUTATION,
      variables: { scope: 'assistant.enabled' },
    });
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(assistant.grantCalls).toEqual([]);
  });
});
