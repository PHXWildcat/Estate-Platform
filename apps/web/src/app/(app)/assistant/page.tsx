import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { ReadinessPanel } from '../../../components/ReadinessPanel';

export const metadata: Metadata = { title: 'Assistant' };

export default function AssistantPage(): ReactElement {
  return (
    <div>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-[1.375rem] font-semibold tracking-tight">Assistant</h1>
          <p className="mt-1 max-w-prose text-sm text-ink-muted">
            Checks run over your own records — what is missing, what contradicts itself, and what
            your estate may owe. Computed, not guessed: the same estate always produces the same
            answer.
          </p>
        </div>
      </div>
      <div className="mt-6">
        <ReadinessPanel />
      </div>
    </div>
  );
}
