import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { ChatPanel } from '../../../../components/ChatPanel';

export const metadata: Metadata = { title: 'Ask the assistant' };

export default function ChatPage(): ReactElement {
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Ask the assistant</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            It reads only what you have allowed, and only your own records. Answers are education,
            not legal or tax advice — and the checks on the readiness page are computed rather than
            written by a model.
          </p>
        </div>
        <Link className="btn btn-secondary" href="/assistant">
          Readiness
        </Link>
      </div>
      <div className="mt-6">
        <ChatPanel />
      </div>
    </div>
  );
}
