/**
 * @jest-environment jsdom
 */

/**
 * THE COPY IS THE CONTROL ON THIS SURFACE.
 *
 * Every refusal an operator meets here is a decision somebody made about a
 * death case, and the sentence is the only part of it they can act on: a
 * dual-control refusal whose remedy is another person must not read as "try
 * again", a voided case must not read as an outage, and a rejected
 * authenticator code must never be explained in the vocabulary of a password
 * (the M12 finding, now on its fourth surface).
 *
 * The set of codes is DERIVED from `ApiFailure`'s own declaration rather than
 * listed here, so a code added to the union arrives with a sentence or turns
 * this red — the failure being prevented is the M9 one, where an unmapped code
 * makes a control firing render as an outage.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ApiFailure } from '../src/client/api';
import { messageFor } from '../src/client/screens';
import { stepUpPrompt } from '../src/client/step-up';

function declaredCodes(): string[] {
  const source = readFileSync(join(__dirname, '..', 'src', 'client', 'api.ts'), 'utf8');
  const start = source.indexOf('export type ApiFailure =');
  expect(start).toBeGreaterThanOrEqual(0);
  const end = source.indexOf(';', start);
  return [...source.slice(start, end).matchAll(/'([A-Z_]+)'/g)].map((m) => m[1] as string);
}

describe('every failure code has a sentence of its own', () => {
  const codes = declaredCodes();

  it('derives the whole union', () => {
    // Anti-vacuity: a scan that matched nothing agrees with any table.
    expect(codes.length).toBeGreaterThanOrEqual(13);
    expect(codes).toContain('OWNER_ALIVE');
    expect(codes).toContain('SEPARATION_OF_DUTIES');
  });

  it('says something for each, and never the fallback for a code that has one', () => {
    const fallback = messageFor('UNKNOWN');
    const spoken = new Map<string, string>();
    for (const code of codes) {
      const text = messageFor(code as ApiFailure);
      expect(text.length).toBeGreaterThan(20);
      spoken.set(code, text);
    }
    // Only UNKNOWN may be the generic sentence. Everything else is a distinct
    // fact about what happened, because the remedies differ.
    const generic = [...spoken.entries()].filter(([, text]) => text === fallback);
    expect(generic.map(([code]) => code)).toEqual(['UNKNOWN']);
  });

  it.each([
    ['OWNER_ALIVE', /confirmed their identity/i, /try again/i],
    ['SEPARATION_OF_DUTIES', /different operator/i, /try again/i],
    ['STATE_CHANGED', /reload/i, /wrong|invalid/i],
    ['FORBIDDEN', /not by signing in here/i, /forbidden/i],
    ['NOT_FOUND', /available to you/i, /exists|deleted/i],
    ['TOO_MANY_ATTEMPTS', /wait/i, /wrong/i],
    ['NETWORK', /has not ended/i, /sign in again/i],
    ['UNAVAILABLE', /nothing was changed/i, /sign in again/i],
  ])('%s says what happened and not what did not', (code, says, never) => {
    const text = messageFor(code as ApiFailure);
    expect(text).toMatch(says);
    expect(text).not.toMatch(never);
  });
});

describe('the step-up prompt explains a refused CODE, never a refused password', () => {
  const say = async (status: number, error: string): Promise<string> => {
    (globalThis as { fetch?: unknown }).fetch = () =>
      Promise.resolve({
        ok: false,
        status,
        text: () => Promise.resolve(JSON.stringify({ error })),
      });
    const { form } = stepUpPrompt({
      hint: 'Confirm it is you.',
      submitLabel: 'Approve',
      idPrefix: 'copy',
      onCancel: () => {},
      onElevated: () => Promise.resolve('applied' as const),
      sleep: () => Promise.resolve(),
    });
    document.body.replaceChildren(form);
    (document.getElementById('copy-stepup-code') as HTMLInputElement).value = '123456';
    (document.querySelector('button[type="submit"]') as HTMLButtonElement).click();
    for (let i = 0; i < 50; i += 1) {
      const text = document.querySelector('.notice')?.textContent ?? '';
      if (text.length > 0) return text;
      await new Promise((r) => setTimeout(r, 0));
    }
    throw new Error('no message');
  };

  it.each([
    [401, 'invalid_credentials'],
    [400, 'invalid_request'],
    [429, 'too_many_attempts'],
    [503, 'unavailable'],
    [500, 'boom'],
  ])('%s %s never mentions a password', async (status, error) => {
    const text = await say(status, error);
    expect(text.length).toBeGreaterThan(20);
    expect(text).not.toMatch(/password/i);
    // Nor does it claim a change was made: every one of these refusals happened
    // before the gated action ran.
    expect(text).not.toMatch(/has been (approved|confirmed|closed)/i);
  });

  it('tells a 400 what to type, and a 503 that nothing changed', async () => {
    expect(await say(400, 'invalid_request')).toMatch(/six digits/i);
    expect(await say(503, 'unavailable')).toMatch(/nothing has changed/i);
    expect(await say(500, 'boom')).toMatch(/could not confirm it was you/i);
  });
});
