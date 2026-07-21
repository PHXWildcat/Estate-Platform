'use client';

import Link from 'next/link';
import { useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { PASSWORD_MIN_LENGTH, validateEmail, validatePassword } from '../lib/validation';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

export function RegisterForm(): ReactElement {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [created, setCreated] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const nextEmailError = validateEmail(email);
    const nextPasswordError = validatePassword(password);
    setEmailError(nextEmailError);
    setPasswordError(nextPasswordError);
    setFormError(null);
    if (nextEmailError !== null || nextPasswordError !== null) return;

    setSubmitting(true);
    const result = await gqlRequest('Register', { email: email.trim(), password });
    setSubmitting(false);
    if (result.ok && result.data.register.ok) {
      setCreated(true);
    } else {
      setFormError(messageFor(result.ok ? 'UNKNOWN' : result.code));
    }
  }

  if (created) {
    return (
      <div className="card p-6" role="status">
        <h2 className="text-lg font-semibold">Your account is ready</h2>
        <p className="mt-2 text-sm text-ink-muted">
          Sign in to continue. We recommend setting up an authenticator app right after — your
          estate deserves more than a password.
        </p>
        <Link className="btn btn-primary mt-4" href="/login">
          Sign in
        </Link>
      </div>
    );
  }

  return (
    <form
      className="card space-y-5 p-6"
      noValidate
      onSubmit={(event) => {
        void handleSubmit(event);
      }}
    >
      <FormField
        id="email"
        label="Email address"
        type="email"
        value={email}
        onChange={setEmail}
        error={emailError}
        autoComplete="email"
        disabled={submitting}
      />
      <FormField
        id="password"
        label="Password"
        type="password"
        value={password}
        onChange={setPassword}
        error={passwordError}
        hint={`At least ${PASSWORD_MIN_LENGTH} characters. A short, memorable sentence works well.`}
        autoComplete="new-password"
        disabled={submitting}
      />
      <FormStatus tone="error" message={formError} />
      <button className="btn btn-primary w-full" type="submit" disabled={submitting}>
        {submitting ? 'Creating account…' : 'Create account'}
      </button>
    </form>
  );
}
