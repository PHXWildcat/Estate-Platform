import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { RegisterForm } from '../../components/RegisterForm';

export const metadata: Metadata = { title: 'Create account' };

export default function RegisterPage(): ReactElement {
  return (
    <div className="mx-auto w-full max-w-md">
      <h1 className="text-2xl font-semibold tracking-tight">Create your account</h1>
      <p className="mb-6 mt-2 text-sm text-ink-muted">
        A few details now; your plans protected for good.
      </p>
      <RegisterForm />
      <p className="mt-4 text-sm text-ink-muted">
        Already have an account?{' '}
        <Link className="text-accent underline underline-offset-2" href="/login">
          Sign in
        </Link>
      </p>
    </div>
  );
}
