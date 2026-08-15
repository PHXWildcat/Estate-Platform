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
  readonly schema: string;
  readonly field: string;
  readonly min: number;
}

/**
 * Every `<something>assword: z.string().min(N)` identity declares, WITH THE
 * SCHEMA IT BELONGS TO.
 *
 * The schema is not decoration — it is the M20 PR5 finding. Two of identity's
 * password fields are both literally named `password`: `RegisterSchema`'s,
 * where the value is about to be STORED and the minimum is a strength rule, and
 * `LoginSchema`'s, where it is about to be compared against a hash and the
 * minimum is a presence check. Keyed on the field name alone the two are
 * indistinguishable, so `RegisterSchema.password` dropping from `min(12)` to
 * `min(1)` was excused as a presence check and satisfied every assertion in
 * this file — including the one whose comment promised it stopped "a future
 * edit satisfying the rule above by making everything `min(1)`", and the
 * header's claim that the assertion is TOTAL.
 */
function declaredMinimums(): Declared[] {
  const text = code();
  const found: Declared[] = [];
  for (const m of text.matchAll(/(\w*[Pp]assword)\s*:\s*z\s*\.string\(\)\s*\.min\((\d+)\)/g)) {
    const before = text.slice(0, m.index);
    const schema = [...before.matchAll(/const (\w+)\s*=\s*z\s*\.object\(/g)].pop();
    found.push({
      schema: schema ? (schema[1] as string) : '<none>',
      field: m[1] as string,
      min: Number(m[2]),
    });
  }
  return found;
}

/** A presence check — "did you type anything" — not a strength rule. */
const PRESENCE = 1;

/**
 * WHICH KIND EACH DECLARATION IS, as data, keyed on the pair rather than on the
 * field. `strength` means the value is about to be STORED, so it must equal
 * this app's minimum; `presence` means it is about to be checked against
 * something already stored, where measuring the length of an existing
 * credential is not the route's business.
 *
 * TOTAL: a declaration missing from this table fails, so identity cannot grow a
 * password field that nobody classified.
 */
const KIND: Readonly<Record<string, 'strength' | 'presence'>> = {
  'RegisterSchema.password': 'strength',
  'LoginSchema.password': 'presence',
  'CompleteResetSchema.newPassword': 'strength',
  'ChangePasswordSchema.currentPassword': 'presence',
  'ChangePasswordSchema.newPassword': 'strength',
  'EmailChangeRequestSchema.currentPassword': 'presence',
};

describe('the password minimum agrees with identity', () => {
  it('finds identity’s password schemas at all (anti-vacuity)', () => {
    // Without this the whole file passes when the regex stops matching — the
    // 2026-08-07 lesson: a fence that stops matching goes green.
    const declared = declaredMinimums();
    expect(declared.length).toBeGreaterThanOrEqual(4);
    expect(declared.some((d) => d.field === 'newPassword')).toBe(true);
    expect(declared.some((d) => d.field === 'currentPassword')).toBe(true);
  });

  it('every declaration is CLASSIFIED — neither list may drift from the other', () => {
    // Both directions, so identity cannot grow a password field nobody
    // classified, and a classification cannot outlive the field it describes.
    const keys = declaredMinimums().map((d) => `${d.schema}.${d.field}`);
    expect([...new Set(keys)].sort()).toEqual(Object.keys(KIND).sort());
  });

  it('every STORED password must be exactly PASSWORD_MIN_LENGTH, and every checked one min(1)', () => {
    // Keyed on the SCHEMA and the field together, which is the whole fix: two
    // of these are named `password`, one stores and one compares, and a
    // field-keyed rule could only ever be right about one of them. Dropping
    // `RegisterSchema.password` to `min(1)` used to satisfy this file.
    const wrong = declaredMinimums()
      .map((d) => ({ ...d, key: `${d.schema}.${d.field}`, kind: KIND[`${d.schema}.${d.field}`] }))
      .filter((d) => (d.kind === 'strength' ? d.min !== PASSWORD_MIN_LENGTH : d.min !== PRESENCE))
      .map(
        (d) =>
          `${d.key} is a ${String(d.kind)} rule but identity says min(${d.min}) ` +
          `(expected ${d.kind === 'strength' ? PASSWORD_MIN_LENGTH : PRESENCE})`,
      );
    expect(wrong).toEqual([]);
  });

  it('at least two schemas STORE a password, and at least two only check one', () => {
    // The floor under the table itself: if every entry drifted to one kind, the
    // rule above would still pass while measuring almost nothing.
    const kinds = Object.values(KIND);
    expect(kinds.filter((k) => k === 'strength').length).toBeGreaterThanOrEqual(2);
    expect(kinds.filter((k) => k === 'presence').length).toBeGreaterThanOrEqual(2);
  });
});
