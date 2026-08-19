/**
 * @jest-environment jsdom
 */

/**
 * THE STEP-UP CEREMONY, and the two properties that are not about the DOM.
 *
 * IT POLLS, because settlement learns of an elevation through
 * `HttpSessionVerifier`'s short-TTL positive cache and a single-shot retry
 * leaves a prompt sitting there doing nothing after an accepted code (M13
 * review round 2, measured against the main app). CANCEL ABORTS THE LOOP,
 * because a step-up prompt is a CONSENT ceremony and an action that proceeds
 * after consent is withdrawn is the one thing it must never do (M13 review
 * round 3, measured: a third `GrantRole` landed after Cancel). Here the stakes
 * are higher than a role grant — a surviving retry could confirm a verification,
 * which locks a living person's account and revokes every session they hold.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  PROPAGATION_BUDGET_MS,
  RETRY_INTERVAL_MS,
  SESSION_CACHE_TTL_MS,
  stepUpPrompt,
  type RetryOutcome,
} from '../src/client/step-up';

interface Reply {
  status: number;
  body: unknown;
}

let calls: string[];

function transport(reply: Reply | (() => Reply)): void {
  calls = [];
  (globalThis as { fetch?: unknown }).fetch = (path: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${path}`);
    const r = typeof reply === 'function' ? reply() : reply;
    return Promise.resolve({
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      text: () => Promise.resolve(r.body === undefined ? '' : JSON.stringify(r.body)),
    });
  };
}

/** Deterministic: the loop's wait is a callback we control, never a real timer. */
function harness(
  outcomes: RetryOutcome[],
  onCancel: () => void = () => {},
): { form: HTMLFormElement; sleeps: number[]; runs: number; now: () => number } {
  const sleeps: number[] = [];
  const state = { runs: 0, clock: 0 };
  jest.spyOn(Date, 'now').mockImplementation(() => state.clock);
  const form = stepUpPrompt({
    hint: 'Confirming a verification locks this account.',
    submitLabel: 'Confirm verification',
    idPrefix: 'verify',
    onCancel,
    onElevated: () => {
      state.runs += 1;
      return Promise.resolve(
        outcomes[Math.min(state.runs - 1, outcomes.length - 1)] as RetryOutcome,
      );
    },
    sleep: (ms) => {
      sleeps.push(ms);
      state.clock += ms;
      return Promise.resolve();
    },
  });
  document.body.replaceChildren(form);
  return {
    form,
    sleeps,
    get runs() {
      return state.runs;
    },
    now: () => state.clock,
  };
}

const field = (): HTMLInputElement =>
  document.getElementById('verify-stepup-code') as HTMLInputElement;
const submit = (): HTMLButtonElement =>
  document.querySelector('button[type="submit"]') as HTMLButtonElement;
const cancel = (): HTMLButtonElement =>
  [...document.querySelectorAll('button')].find(
    (b) => b.textContent === 'Cancel',
  ) as HTMLButtonElement;
const notice = (): string => document.querySelector('.notice')?.textContent ?? '';

/** Poll to a deadline rather than racing a fixed number of microtasks. */
async function until(condition: () => boolean): Promise<void> {
  for (let i = 0; i < 200; i += 1) {
    if (condition()) return;
    await new Promise((r) => setTimeout(r, 0));
  }
  throw new Error('condition never held');
}

afterEach(() => {
  jest.restoreAllMocks();
});

describe('the propagation budget is MIRRORED from auth-guard, not guessed', () => {
  /*
   * The web app cannot import a NestJS package, so the number is duplicated —
   * and a number duplicated without a check is a number that drifts. This is
   * the compose-parity mechanism: read the file that OWNS the value and assert
   * agreement, so raising the peer's TTL moves this budget rather than silently
   * making the prompt give up before the cache expires.
   */
  const verifier = readFileSync(
    join(__dirname, '..', '..', '..', 'packages', 'auth-guard', 'src', 'verifier.ts'),
    'utf8',
  );

  it('equals DEFAULT_CACHE_TTL_MS in packages/auth-guard/src/verifier.ts', () => {
    // PARSED, NOT EVALUATED — the main app's own pin, verbatim: `new Function`
    // is an implied eval, and a test that reaches for one to read a constant is
    // a test that could RUN the file it is only supposed to inspect. The
    // declaration is `<n> * <m>` or a plain number; anything else is a spelling
    // change worth failing on, because it means the value stopped being the
    // simple literal this check can verify.
    const match = /const DEFAULT_CACHE_TTL_MS = ([0-9_]+)(?:\s*\*\s*([0-9_]+))?;/.exec(verifier);
    // Anti-vacuity: a scan that matched nothing agrees with any number.
    expect(match).not.toBeNull();
    const [, left, right] = match as RegExpExecArray;
    const declared =
      Number(left?.replace(/_/g, '')) * (right === undefined ? 1 : Number(right.replace(/_/g, '')));
    expect(declared).toBeGreaterThan(0);
    expect(SESSION_CACHE_TTL_MS).toBe(declared);
  });

  it('waits PAST the TTL, so the last attempt lands after it has certainly expired', () => {
    expect(PROPAGATION_BUDGET_MS).toBeGreaterThan(SESSION_CACHE_TTL_MS);
    // …and long enough to take several attempts rather than one hopeful retry.
    expect(PROPAGATION_BUDGET_MS / RETRY_INTERVAL_MS).toBeGreaterThanOrEqual(5);
  });
});

describe('the step-up prompt', () => {
  it('REFUSES A MALFORMED CODE WITHOUT ASKING IDENTITY', async () => {
    transport({ status: 200, body: {} });
    harness(['applied']);
    field().value = '12';
    submit().click();
    await until(() => notice().length > 0);
    expect(calls).toEqual([]);
    expect(notice()).toMatch(/six digits/i);
  });

  it('POLLS until the peer catches up, and then applies', async () => {
    transport({ status: 200, body: {} });
    const h = harness(['stale', 'stale', 'applied']);
    field().value = '123456';
    submit().click();
    await until(() => h.runs === 3);

    expect(calls).toEqual(['POST /api/auth/stepup']);
    // One elevation, three attempts at the action: the retry is against the
    // PEER's cache, not against identity.
    expect(h.sleeps).toEqual([RETRY_INTERVAL_MS, RETRY_INTERVAL_MS]);
    await until(() => submit().disabled === false);
    expect(notice()).toBe('');
  });

  it('GIVES UP AT THE DEADLINE and says the check itself went through', async () => {
    transport({ status: 200, body: {} });
    const h = harness(['stale']);
    field().value = '123456';
    submit().click();
    await until(() => notice().length > 0);

    expect(h.now()).toBeGreaterThanOrEqual(PROPAGATION_BUDGET_MS);
    expect(notice()).toMatch(/went through/i);
    expect(notice()).toMatch(/has not caught up/i);
    // Never "that code was wrong": it was not.
    expect(notice()).not.toMatch(/not accepted/i);
    expect(submit().disabled).toBe(false);
  });

  it('CANCEL ABORTS THE LOOP — nothing is applied after consent is withdrawn', async () => {
    /*
     * THE SLEEP IS HELD OPEN so Cancel lands while the loop is genuinely
     * parked, which is the only state in which the abort is observable.
     *
     * The first version of this test used the immediate fake sleep and PASSED
     * with the abort deleted: the loop had already run to its deadline before
     * the click, so "no further runs after Cancel" was true for the wrong
     * reason. A test of a race must hold the race open.
     */
    transport({ status: 200, body: {} });
    let release: (() => void) | null = null;
    let cancelled = 0;
    const state = { runs: 0, clock: 0 };
    jest.spyOn(Date, 'now').mockImplementation(() => state.clock);
    const form = stepUpPrompt({
      hint: 'h',
      submitLabel: 'Confirm verification',
      idPrefix: 'verify',
      onCancel: () => {
        cancelled += 1;
      },
      onElevated: () => {
        state.runs += 1;
        return Promise.resolve('stale' as const);
      },
      sleep: () =>
        new Promise<void>((resolve) => {
          release = () => {
            state.clock += RETRY_INTERVAL_MS;
            resolve();
          };
        }),
    });
    document.body.replaceChildren(form);

    field().value = '123456';
    submit().click();
    await until(() => release !== null);
    expect(state.runs).toBe(1);

    cancel().click();
    (release as unknown as () => void)();
    // Drain generously: a surviving retry would land right about here.
    for (let i = 0; i < 20; i += 1) await new Promise((r) => setTimeout(r, 0));
    expect(state.runs).toBe(1);
    expect(cancelled).toBe(1);
  });

  it('CANCEL RESTORES THE FORM ITSELF, without waiting for the request it cancels', () => {
    // Neither await carries a timeout, so a stalled identity call would leave a
    // declined consent form disabled forever — the protective action must not
    // be contingent on the permissive one finishing.
    calls = [];
    (globalThis as { fetch?: unknown }).fetch = () => new Promise(() => {});
    const h = harness(['applied']);
    field().value = '123456';
    submit().click();
    expect(submit().disabled).toBe(true);
    cancel().click();
    expect(submit().disabled).toBe(false);
    expect(submit().textContent).toBe('Confirm verification');
    expect(h.runs).toBe(0);
  });

  it('A FRESH SUBMISSION OWNS THE FORM, and the abandoned one cannot apply', async () => {
    // A counter rather than a boolean: `submit()` re-arms consent on the way in,
    // so a boolean would let the abandoned request see consent restored BY A
    // DIFFERENT submission and run the action twice.
    let release: (() => void) | null = null;
    calls = [];
    (globalThis as { fetch?: unknown }).fetch = () =>
      new Promise((resolve) => {
        release = () =>
          resolve({
            ok: true,
            status: 200,
            text: () => Promise.resolve('{}'),
          });
      });
    const h = harness(['applied']);
    field().value = '123456';
    submit().click();
    cancel().click();
    field().value = '654321';
    submit().click();
    (release as unknown as () => void)();
    for (let i = 0; i < 20; i += 1) await new Promise((r) => setTimeout(r, 0));
    // Exactly one of the two in-flight elevations owns the form, so the action
    // ran once — never twice.
    expect(h.runs).toBeLessThanOrEqual(1);
  });

  it('NEVER EXPLAINS A REFUSED CODE IN THE VOCABULARY OF A PASSWORD', async () => {
    // Identity answers `invalid_credentials` for a wrong TOTP code exactly as
    // for a wrong password (the M12 finding, fixed on three surfaces since) and
    // this form has no password on it.
    transport({ status: 401, body: { error: 'invalid_credentials' } });
    const h = harness(['applied']);
    field().value = '123456';
    submit().click();
    await until(() => notice().length > 0);
    expect(notice()).toMatch(/30 seconds/);
    expect(notice()).not.toMatch(/password/i);
    expect(h.runs).toBe(0);
  });

  it('reports the step-up CAP as a control firing, not as a wrong code', async () => {
    transport({ status: 429, body: { error: 'too_many_attempts' } });
    harness(['applied']);
    field().value = '123456';
    submit().click();
    await until(() => notice().length > 0);
    expect(notice()).toMatch(/too many attempts/i);
    expect(notice()).toMatch(/may have been fine/i);
  });

  it('associates its label with its field, and names the field once', () => {
    harness(['applied']);
    const label = document.querySelector('label') as HTMLLabelElement;
    expect(label.htmlFor).toBe('verify-stepup-code');
    expect(document.querySelectorAll('#verify-stepup-code')).toHaveLength(1);
  });
});
