import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { SecurityPanel } from '../../components/SecurityPanel';

export const metadata: Metadata = { title: 'Security' };

export default function SecurityPage(): ReactElement {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
      <p className="mb-6 mt-2 max-w-prose text-sm text-ink-muted">
        Manage the protections on your account: authenticator enrollment, step-up verification for
        sensitive actions, and data export.
      </p>
      <SecurityPanel />
    </div>
  );
}
