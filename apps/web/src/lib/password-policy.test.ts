/**
 * THE PASSWORD MINIMUM IS ONE NUMBER IN FOUR PLACES, and until M20 PR1 nothing
 * compared them.
 *
 * `PASSWORD_MIN_LENGTH` (12) is the hint this app prints and the rule
 * `validatePassword` enforces before sending. Identity declares the same number
 * independently, three times — registration, the password change, and the reset
 * completion. Nothing checked that they agree, so identity raising its minimum
 * would leave this app promising a length the server refuses, and the user
 * would meet it as a bare `INVALID_REQUEST` after typing a password twice.
 *
 * The mirror is deliberate and is NOT a control: identity's zod schema is the
 * gate, and the M12 upload-client rule says a client must not hold a second
 * opinion about a server-side decision. What a client MAY do is mirror a
 * server's number as a usability hint — which is exactly what M12 itself did
 * with the upload size cap. This fence is what keeps "mirror" true and stops it
 * quietly becoming "guess".
 *
 * MECHANISM: read identity's source as TEXT. The web app cannot import a Nest
 * package, so this is the compose-parity / step-up.test.ts mechanism — the same
 * answer this repo reaches for whenever one fact has to hold across a boundary
 * the module graph does not cross.
 *
 * THE ASSERTION IS TOTAL, not a search for the values we expect: every
 * password-ish field in identity's wire schemas must be EITHER a presence check
 * (`min(1)` — "did you type anything", used for the CURRENT password and for
 * login, where length is not the server's business) OR exactly
 * `PASSWORD_MIN_LENGTH`. A third value is a failure whichever direction it
 * moves, which is what makes this catch a raise as well as a drop.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PASSWORD_MIN_LENGTH } from './validation';

const IDENTITY_CONTROLLER = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'apps',
  'services',
  'identity',
  'src',
  'auth.controller.ts',
);

/** Comments stripped: a scan of source means a scan of CODE. */
function code(): string {
  return readFileSync(IDENTITY_CONTROLLER, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '');
}

interface Declared {
  readonly field: string;
  readonly min: number;
}

/** Every `<something>assword: z.string().min(N)` identity declares. */
function declaredMinimums(): Declared[] {
  const found: Declared[] = [];
  for (const m of code().matchAll(/(\w*[Pp]assword)\s*:\s*z\s*\.string\(\)\s*\.min\((\d+)\)/g)) {
    found.push({ field: m[1] as string, min: Number(m[2]) });
  }
  return found;
}

/** A presence check — "did you type anything" — not a strength rule. */
const PRESENCE = 1;

describe('the password minimum agrees with identity', () => {
  it('finds identity’s password schemas at all (anti-vacuity)', () => {
    // Without this the whole file passes when the regex stops matching — the
    // 2026-08-07 lesson: a fence that stops matching goes green.
    const declared = declaredMinimums();
    expect(declared.length).toBeGreaterThanOrEqual(4);
    expect(declared.some((d) => d.field === 'newPassword')).toBe(true);
    expect(declared.some((d) => d.field === 'currentPassword')).toBe(true);
  });

  it('every strength-carrying minimum equals PASSWORD_MIN_LENGTH', () => {
    const wrong = declaredMinimums()
      .filter((d) => d.min !== PRESENCE && d.min !== PASSWORD_MIN_LENGTH)
      .map((d) => `${d.field}: identity says min(${d.min}), this app says ${PASSWORD_MIN_LENGTH}`);
    expect(wrong).toEqual([]);
  });

  it('the CURRENT password is a presence check, and the NEW one is not', () => {
    // Names which is which, so a future edit cannot satisfy the rule above by
    // making everything `min(1)`. Identity must not start measuring the length
    // of a password it is about to verify against a stored hash (the length of
    // an existing credential is not the change route's business), and it must
    // not stop measuring the one it is about to store.
    const declared = declaredMinimums();
    for (const d of declared.filter((x) => x.field === 'currentPassword')) {
      expect(d.min).toBe(PRESENCE);
    }
    const news = declared.filter((x) => x.field === 'newPassword');
    expect(news.length).toBeGreaterThanOrEqual(2); // the change AND the reset
    for (const d of news) {
      expect(d.min).toBe(PASSWORD_MIN_LENGTH);
    }
  });
});
