import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  SESSION_CACHE_TTL_MS,
  STEP_UP_PROPAGATION_BUDGET_MS,
  STEP_UP_RETRY_INTERVAL_MS,
} from './step-up';

/**
 * A NUMBER DUPLICATED WITHOUT A CHECK IS A NUMBER THAT DRIFTS — the M11 lesson
 * (a timeout whose comment said the opposite of what it did) and the M8
 * compose-parity mechanism (read the other file and assert agreement, because
 * this app cannot import a Nest package).
 *
 * The retry window only means anything if it outlasts the peer's session cache.
 * If someone raises `DEFAULT_CACHE_TTL_MS` in @estate/auth-guard, this test
 * fails here rather than the prompt quietly giving up too early again.
 */
const VERIFIER = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'packages',
  'auth-guard',
  'src',
  'verifier.ts',
);

describe('the step-up propagation window tracks the session cache it exists for', () => {
  it('mirrors auth-guard’s DEFAULT_CACHE_TTL_MS exactly', () => {
    const source = readFileSync(VERIFIER, 'utf8');
    // Parsed, not evaluated: `new Function` is an implied eval, and a test that
    // reaches for one to read a constant is a test that could run the file it is
    // only supposed to inspect. The declaration is `<n> * <m>` or a plain
    // number — anything else is a spelling change worth failing on, because it
    // means the value stopped being a simple literal this check can verify.
    const match = /const DEFAULT_CACHE_TTL_MS = ([0-9_]+)(?:\s*\*\s*([0-9_]+))?;/.exec(source);
    expect(match).not.toBeNull();
    const [, left, right] = match as RegExpExecArray;
    const declared =
      Number(left?.replace(/_/g, '')) * (right === undefined ? 1 : Number(right.replace(/_/g, '')));
    expect(declared).toBeGreaterThan(0);
    expect(SESSION_CACHE_TTL_MS).toBe(declared);
  });

  it('waits LONGER than the cache, so the last attempt lands after it expires', () => {
    expect(STEP_UP_PROPAGATION_BUDGET_MS).toBeGreaterThan(SESSION_CACHE_TTL_MS);
    // ...and retries often enough to actually make attempts inside the window.
    expect(STEP_UP_RETRY_INTERVAL_MS).toBeLessThan(SESSION_CACHE_TTL_MS / 2);
  });
});
