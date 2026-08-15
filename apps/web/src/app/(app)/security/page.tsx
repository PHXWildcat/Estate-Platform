import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { AccountSecurity } from '../../../components/AccountSecurity';

export const metadata: Metadata = { title: 'Security' };

export default function SecurityPage(): ReactElement {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
      <p className="mb-6 mt-2 max-w-prose text-sm text-ink-muted">
        Manage the protections on your account: your password and sign-in address, authenticator
        enrollment, step-up verification for sensitive actions, and data export.
      </p>
      {/* The two panels below share one fact — see `AccountSecurity`. */}
      <AccountSecurity />
    </div>
  );
}
