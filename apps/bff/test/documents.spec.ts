import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import {
  DOCUMENT,
  DOCUMENT_CONTENT,
  DOCUMENT_VERSION,
  FakeDocumentsClient,
  TEMPLATE,
  TOKENS,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * The documents resolvers (M12). Same trust model as assets and the assistant —
 * the caller's own bearer goes downstream and nothing else — so the assertions
 * that matter are the token flow, the intake collapsing (the one place this
 * layer makes a decision rather than forwarding one), and the fact that no
 * query can produce content the caller did not explicitly ask for.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const TEMPLATES_QUERY =
  'query DocumentTemplates($state: String!) { documentTemplates(state: $state) { templateId docType state version legalReviewAt executionRequirements { witnesses notarization selfProvingAffidavit } variables { name kind label required maxLength options } } }';
const DOCUMENTS_QUERY =
  'query Documents { documents { documentId docType source title currentVersion executionStatus executedAt legalHold sealed templateId createdAt updatedAt } }';
const DOCUMENT_QUERY =
  'query Document($documentId: ID!) { document(documentId: $documentId) { documentId title executionStatus currentVersion } }';
const VERSIONS_QUERY =
  'query DocumentVersions($documentId: ID!) { documentVersions(documentId: $documentId) { version contentSha256 sizeBytes mime createdAt } }';
const CONTENT_QUERY =
  'query DocumentContent($documentId: ID!, $version: Int!) { documentContent(documentId: $documentId, version: $version) { documentId version mime contentSha256 encoding content } }';
const GENERATE_MUTATION =
  'mutation GenerateDocument($docType: String!, $state: String!, $templateId: ID, $title: String, $variables: [DocumentVariableInput!]!) { generateDocument(docType: $docType, state: $state, templateId: $templateId, title: $title, variables: $variables) { documentId version contentSha256 executionStatus } }';
const REGENERATE_MUTATION =
  'mutation RegenerateDocument($documentId: ID!, $templateId: ID, $title: String, $variables: [DocumentVariableInput!]!) { regenerateDocument(documentId: $documentId, templateId: $templateId, title: $title, variables: $variables) { documentId version } }';

describe('documents resolvers', () => {
  let app: INestApplication;
  let documents: FakeDocumentsClient;

  beforeEach(async () => {
    documents = new FakeDocumentsClient();
    app = await makeApp({ documents });
  });

  afterEach(async () => {
    await app.close();
  });

  it('forwards the CALLER’S bearer token on every read', async () => {
    await gql(app, { query: DOCUMENTS_QUERY }, { cookie: COOKIE });
    await gql(
      app,
      { query: DOCUMENT_QUERY, variables: { documentId: DOCUMENT.documentId } },
      { cookie: COOKIE },
    );
    await gql(app, { query: TEMPLATES_QUERY, variables: { state: 'CA' } }, { cookie: COOKIE });
    expect(documents.listCalls).toEqual([TOKENS.accessToken]);
    expect(documents.getCalls).toEqual([
      { accessToken: TOKENS.accessToken, documentId: DOCUMENT.documentId },
    ]);
    expect(documents.templatesCalls).toEqual([{ accessToken: TOKENS.accessToken, state: 'CA' }]);
  });

  it('answers UNAUTHENTICATED without a session cookie, and calls nothing', async () => {
    const res = await gql(app, { query: DOCUMENTS_QUERY });
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('UNAUTHENTICATED');
    expect(documents.listCalls).toEqual([]);
  });

  it('returns the template catalog with its formalities and intake declarations', async () => {
    const res = await gql(
      app,
      { query: TEMPLATES_QUERY, variables: { state: 'CA' } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(gqlBody(res).data?.['documentTemplates']).toEqual([
      {
        ...TEMPLATE,
        variables: [
          { ...TEMPLATE.variables[0], options: null },
          { ...TEMPLATE.variables[1], maxLength: null, options: null },
        ],
      },
    ]);
  });

  it('lists documents as METADATA ONLY — no query path decrypts anything', async () => {
    const res = await gql(app, { query: DOCUMENTS_QUERY }, { cookie: COOKIE });
    expect(gqlBody(res).data?.['documents']).toEqual([DOCUMENT]);
    // The load-bearing assertion: listing is not a decrypt. Every content read
    // is an audited KMS operation on the user's own trail, so a list that
    // fetched content would turn one page load into N such events.
    expect(documents.contentCalls).toEqual([]);
  });

  it('reads content only for the exact version asked for', async () => {
    const res = await gql(
      app,
      { query: CONTENT_QUERY, variables: { documentId: DOCUMENT.documentId, version: 1 } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).data?.['documentContent']).toEqual(DOCUMENT_CONTENT);
    expect(documents.contentCalls).toEqual([
      { accessToken: TOKENS.accessToken, documentId: DOCUMENT.documentId, version: 1 },
    ]);
  });

  it('passes a version list through', async () => {
    const res = await gql(
      app,
      { query: VERSIONS_QUERY, variables: { documentId: DOCUMENT.documentId } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).data?.['documentVersions']).toEqual([DOCUMENT_VERSION]);
  });

  it('surfaces the step-up refusal as a code the client can act on', async () => {
    documents.documentsError = bffError('STEPUP_REQUIRED');
    const res = await gql(
      app,
      {
        query: GENERATE_MUTATION,
        variables: { docType: 'will', state: 'CA', variables: [] },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.code).toBe('STEPUP_REQUIRED');
  });
});

describe('intake collapsing', () => {
  let app: INestApplication;
  let documents: FakeDocumentsClient;

  beforeEach(async () => {
    documents = new FakeDocumentsClient();
    app = await makeApp({ documents });
  });

  afterEach(async () => {
    await app.close();
  });

  async function generate(variables: unknown): Promise<ReturnType<typeof gqlBody>> {
    const res = await gql(
      app,
      { query: GENERATE_MUTATION, variables: { docType: 'will', state: 'CA', variables } },
      { cookie: COOKIE },
    );
    return gqlBody(res);
  }

  it('collapses the typed list into the record the service takes', async () => {
    const body = await generate([
      { name: 'testatorName', text: 'Ada Lovelace' },
      { name: 'hasMinorChildren', boolean: true },
    ]);
    expect(body.errors).toBeUndefined();
    expect(documents.generateCalls[0]?.input.variables).toEqual({
      testatorName: 'Ada Lovelace',
      hasMinorChildren: true,
    });
  });

  it('refuses a variable carrying NEITHER value', async () => {
    // The renderer fails closed on an unsubstitutable placeholder two layers
    // away; refusing here is the difference between "that answer was malformed"
    // and a generic downstream 422.
    const body = await generate([{ name: 'testatorName' }]);
    expect(body.errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
    expect(documents.generateCalls).toEqual([]);
  });

  it('refuses a variable carrying BOTH values', async () => {
    const body = await generate([{ name: 'testatorName', text: 'Ada', boolean: false }]);
    expect(body.errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
    expect(documents.generateCalls).toEqual([]);
  });

  it('refuses a DUPLICATE name rather than letting last-write-wins decide', async () => {
    // Otherwise the value the user saw in the form and the value rendered into
    // the instrument could differ, with nothing in between to notice.
    const body = await generate([
      { name: 'testatorName', text: 'Ada Lovelace' },
      { name: 'testatorName', text: 'Someone Else' },
    ]);
    expect(body.errors?.[0]?.extensions?.code).toBe('INVALID_REQUEST');
    expect(documents.generateCalls).toEqual([]);
  });

  it('accepts an empty answer set and lets the TEMPLATE decide it is incomplete', async () => {
    // What a variable may contain is the template's declaration to enforce; a
    // second copy of that gate here would drift from the legal one.
    const body = await generate([]);
    expect(body.errors).toBeUndefined();
    expect(documents.generateCalls[0]?.input.variables).toEqual({});
  });

  it('omits an absent title rather than sending an empty one', async () => {
    await generate([]);
    expect(documents.generateCalls[0]?.input.title).toBeUndefined();
  });

  it('omits a BLANK title too, rather than forwarding whitespace as a label', async () => {
    const res = await gql(
      app,
      {
        query: GENERATE_MUTATION,
        variables: { docType: 'will', state: 'CA', title: '', variables: [] },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(documents.generateCalls[0]?.input.title).toBeUndefined();
  });

  it('forwards a pinned template and a title when they are supplied', async () => {
    const res = await gql(
      app,
      {
        query: GENERATE_MUTATION,
        variables: {
          docType: 'will',
          state: 'CA',
          templateId: TEMPLATE.templateId,
          title: 'My will',
          variables: [],
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(documents.generateCalls[0]?.input).toEqual({
      docType: 'will',
      state: 'CA',
      templateId: TEMPLATE.templateId,
      title: 'My will',
      variables: {},
    });
  });

  it('applies the same collapsing to a regeneration', async () => {
    const res = await gql(
      app,
      {
        query: REGENERATE_MUTATION,
        variables: {
          documentId: DOCUMENT.documentId,
          variables: [{ name: 'testatorName', text: 'Ada' }],
        },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors).toBeUndefined();
    expect(documents.regenerateCalls[0]).toEqual({
      accessToken: TOKENS.accessToken,
      documentId: DOCUMENT.documentId,
      input: { variables: { testatorName: 'Ada' } },
    });
  });
});
