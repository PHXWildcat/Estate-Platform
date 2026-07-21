import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement } from 'react';
import { LoginForm } from '../../components/LoginForm';

export const metadata: Metadata = { title: 'Sign in' };

export default function LoginPage(): ReactElement {
  return (
    <div className="mx-auto w-full max-w-md">
      <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
      <p className="mb-6 mt-2 text-sm text-ink-muted">Welcome back.</p>
      <LoginForm />
      <p className="mt-4 text-sm text-ink-muted">
        New here?{' '}
        <Link className="text-accent underline underline-offset-2" href="/register">
          Create an account
        </Link>
      </p>
    </div>
  );
}
