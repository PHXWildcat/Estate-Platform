/**
 * Client-side validation mirroring the server's rules. Purely a UX layer —
 * the BFF and identity service re-validate everything.
 */

export const PASSWORD_MIN_LENGTH = 12;

// Deliberately permissive shape check (something@something.tld). The server
// owns real address validation; this only catches obvious slips early.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateEmail(email: string): string | null {
  if (email.trim().length === 0) return 'Enter your email address.';
  if (!EMAIL_PATTERN.test(email.trim())) {
    return 'Enter a valid email address, like name@example.com.';
  }
  return null;
}

export function validatePassword(password: string): string | null {
  if (password.length === 0) return 'Enter a password.';
  if (password.length < PASSWORD_MIN_LENGTH) {
    return `Use at least ${PASSWORD_MIN_LENGTH} characters. Longer passphrases are stronger and easier to remember.`;
  }
  return null;
}

export function validateTotpCode(code: string): string | null {
  if (code.trim().length === 0) return 'Enter the 6-digit code from your authenticator app.';
  if (!/^\d{6}$/.test(code.trim())) return 'The code is 6 digits, numbers only.';
  return null;
}
