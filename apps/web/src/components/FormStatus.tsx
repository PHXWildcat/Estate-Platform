'use client';

import type { ReactElement } from 'react';

interface FormStatusProps {
  tone: 'error' | 'success' | 'info';
  /** Message to announce, or null. The live region stays mounted either way. */
  message: string | null;
}

const toneClasses: Record<FormStatusProps['tone'], string> = {
  error: 'text-danger',
  success: 'rounded-field bg-success-surface px-3 py-2 text-success',
  info: 'text-ink-muted',
};

/**
 * Always-mounted polite live region for form-level outcomes, so screen
 * readers announce content that arrives after submit.
 */
export function FormStatus({ tone, message }: FormStatusProps): ReactElement {
  return (
    <div role="status" aria-live="polite">
      {message !== null ? <p className={`text-sm ${toneClasses[tone]}`}>{message}</p> : null}
    </div>
  );
}
