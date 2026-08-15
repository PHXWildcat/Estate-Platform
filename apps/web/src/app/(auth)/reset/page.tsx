import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { PasswordResetForm } from '../../../components/PasswordResetForm';

export const metadata: Metadata = { title: 'Reset your password' };

export default function ResetPage(): ReactElement {
  return (
    <div className="mx-auto w-full max-w-md">
      <h1 className="text-2xl font-semibold tracking-tight">Reset your password</h1>
      <p className="mb-6 mt-2 text-sm text-ink-muted">
        We’ll email a code to the address on your account. There is nothing to click in that email —
        you enter the code here.
      </p>
      <PasswordResetForm />
      <p className="mt-4 text-sm text-ink-muted">
        Remembered it?{' '}
        <Link className="text-accent underline underline-offset-2" href="/login">
          Sign in
        </Link>
      </p>
    </div>
  );
}
