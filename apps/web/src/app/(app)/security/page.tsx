import type { Metadata } from 'next';
import type { ReactElement } from 'react';
import { EmailVerificationPanel } from '../../../components/EmailVerificationPanel';
import { SecurityPanel } from '../../../components/SecurityPanel';

export const metadata: Metadata = { title: 'Security' };

export default function SecurityPage(): ReactElement {
  return (
    <div>
      <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
      <p className="mb-6 mt-2 max-w-prose text-sm text-ink-muted">
        Manage the protections on your account: authenticator enrollment, step-up verification for
        sensitive actions, and data export.
      </p>
      <section className="mb-8">
        <h2 className="text-lg font-medium tracking-tight">Email address</h2>
        <p className="mb-3 mt-1 max-w-prose text-sm text-ink-muted">
          Confirming your address is what lets us reach you when someone tries to open your estate —
          and some protections stay switched off until you do.
        </p>
        <EmailVerificationPanel />
      </section>
      <SecurityPanel />
    </div>
  );
}
