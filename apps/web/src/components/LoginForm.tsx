'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent, type ReactElement } from 'react';
import { gqlRequest } from '../graphql/client';
import { messageFor } from '../lib/copy';
import { validateEmail, validatePassword } from '../lib/validation';
import { FormField } from './FormField';
import { FormStatus } from './FormStatus';

export function LoginForm(): ReactElement {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const nextEmailError = validateEmail(email);
    const nextPasswordError = validatePassword(password);
    setEmailError(nextEmailError);
    setPasswordError(nextPasswordError);
    setFormError(null);
    if (nextEmailError !== null || nextPasswordError !== null) return;

    setSubmitting(true);
    const result = await gqlRequest('Login', { email: email.trim(), password });
    if (result.ok && result.data.login.ok) {
      // Auth cookie is now set (httpOnly, by the BFF). Nothing to store here.
      router.push('/');
      return;
    }
    setSubmitting(false);
    setFormError(messageFor(result.ok ? 'UNKNOWN' : result.code));
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
        autoComplete="current-password"
        disabled={submitting}
      />
      <FormStatus tone="error" message={formError} />
      <button className="btn btn-primary w-full" type="submit" disabled={submitting}>
        {submitting ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  );
}
