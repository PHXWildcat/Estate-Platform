/**
 * @jest-environment jsdom
 */

/**
 * PROVING A FACTOR ON THE VAULT ORIGIN (M15 review).
 *
 * Handoff redemption no longer grants step-up: it used to, and that let whoever
 * held a stolen 60-second code reach `POST /v1/vault/reset`, which is gated on
 * step-up ALONE because a lost vault password cannot be proven. So the gated
 * actions have to be able to ask here instead, through the `/v1/auth/stepup`
 * route PR1 widened for the `vault` audience and then left unwired.
 *
 * Every case below is about the ceremony rather than the happy path, because
 * the ways a consent prompt goes wrong are what this repo keeps finding: it
 * proceeds after a cancel, it reports success on a refusal, or it sends a
 * malformed value and spends an attempt.
 */
import { promptForStepUp, stepUp } from '../src/client/stepup';
import type { ApiFailure } from '../src/client/api';

type Reply = { status: number; body: unknown };

function serviceAnswering(answers: Reply[]): { calls: Array<{ path: string; body: string }> } {
  const calls: Array<{ path: string; body: string }> = [];
  let index = 0;
  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    calls.push({ path, body: typeof init.body === 'string' ? init.body : '' });
    const answer = answers[Math.min(index++, answers.length - 1)] ?? { status: 200, body: {} };
    return Promise.resolve({
      ok: answer.status >= 200 && answer.status < 300,
      status: answer.status,
      text: () => Promise.resolve(JSON.stringify(answer.body)),
    });
  }) as unknown as typeof fetch;
  return { calls };
}

const messageFor = (code: ApiFailure): string => `generic:${code}`;

function host(): HTMLElement {
  const node = document.createElement('div');
  document.body.replaceChildren(node);
  return node;
}

const click = (text: string): void => {
  const button = [...document.querySelectorAll('button')].find((b) =>
    b.textContent?.includes(text),
  );
  if (!button) throw new Error(`no button "${text}". Saw: ${document.body.textContent}`);
  button.click();
};

const type = (value: string): void => {
  (document.getElementById('stepup-code') as HTMLInputElement).value = value;
};

const submit = (): void => {
  document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true }));
};

const settle = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 20));

/*
 * READ THE ERROR NODE, NEVER `document.body.textContent` (M44 PR1).
 *
 * The test this replaces asserted `/codes last about 30 seconds/i` against the
 * whole body — and the FORM'S OWN HINT is "From your authenticator app. Codes
 * last about 30 seconds.", present in the DOM from the moment the prompt
 * renders. So the assertion matched the hint rather than the refusal and could
 * not fail: measured, it stayed green when the fixture was pointed at a 503
 * rendering an entirely different sentence, and it stayed green when the
 * special-casing branch it was written to protect was DELETED outright.
 *
 * Scoping the read to `p.status-error` is what makes these assertions about the
 * refusal at all. `theHintIsAlwaysPresent` below is the control that keeps this
 * comment honest.
 */
const refusalText = (): string => document.querySelector('p.status-error')?.textContent ?? '';

/**
 * Drive the prompt to one refusal and return what it SAID about it.
 *
 * `messageFor` here is the stub `generic:<CODE>`, deliberately: THIS FILE PROVES
 * THE WIRING — which `ApiFailure` the prompt resolves a given wire answer to,
 * and that it adds no special-casing of its own. Whether those codes map to
 * distinct English is a different layer, proved in `copy.spec.ts` against the
 * real `messageFor`; and whether identity actually sends these tokens is a third,
 * proved on the wire in `apps/e2e/test/vault.e2e.spec.ts`.
 */
async function refuse(status: number, token: string): Promise<string> {
  serviceAnswering([{ status, body: { error: token } }]);
  void promptForStepUp(host(), 'Resetting the vault', messageFor);
  type('123456');
  submit();
  await settle();
  return refusalText();
}

describe('the step-up prompt', () => {
  it('posts the code to identity through this origin', async () => {
    const service = serviceAnswering([{ status: 200, body: { mfaLevel: 'stepup' } }]);
    expect((await stepUp('123456')).ok).toBe(true);
    expect(service.calls[0]?.path).toBe('/api/auth/stepup');
    expect(JSON.parse(service.calls[0]?.body ?? '{}')).toEqual({ code: '123456' });
  });

  it('resolves ELEVATED only after identity accepted it', async () => {
    serviceAnswering([{ status: 200, body: { mfaLevel: 'stepup' } }]);
    const outcome = promptForStepUp(host(), 'Resetting the vault', messageFor);
    type('123456');
    submit();
    await expect(outcome).resolves.toBe('elevated');
  });

  it('CANCEL resolves cancelled and sends nothing', async () => {
    // A consent ceremony that proceeds after consent is withdrawn is the M13
    // round-3 defect. Cancel must be terminal, and must not have asked.
    const service = serviceAnswering([{ status: 200, body: {} }]);
    const outcome = promptForStepUp(host(), 'Resetting the vault', messageFor);
    click('Cancel');
    await expect(outcome).resolves.toBe('cancelled');
    expect(service.calls).toHaveLength(0);
  });

  it('refuses a malformed code BEFORE the network, so a typo costs no attempt', async () => {
    const service = serviceAnswering([{ status: 200, body: {} }]);
    void promptForStepUp(host(), 'Resetting the vault', messageFor);
    type('12345');
    submit();
    await settle();
    expect(service.calls).toHaveLength(0);
    expect(document.body.textContent).toMatch(/enter the six digits/i);
  });

  it('CONTROL: the hint says "codes last about 30 seconds" before any refusal', () => {
    // The reason every assertion below reads `p.status-error` rather than the
    // body. If this ever stops being true the scoping is no longer load-bearing
    // and these tests should be re-examined rather than quietly relaxed.
    serviceAnswering([{ status: 200, body: {} }]);
    void promptForStepUp(host(), 'Resetting the vault', messageFor);
    expect(document.body.textContent).toMatch(/codes last about 30 seconds/i);
    expect(refusalText()).toBe('');
  });

  it('says what THIS form holds when a CODE is refused, not "email and password"', async () => {
    // `invalid_code` is what identity actually answers here (auth.service.ts).
    // The replaced test used `invalid_credentials` — the LOGIN refusal, a token
    // this route never sends.
    const shown = await refuse(401, 'invalid_code');
    expect(shown).toBe('generic:INVALID_CODE');
    expect(shown).not.toMatch(/email/i);
  });

  it('a refusal is not a cancel — the prompt stays open', async () => {
    serviceAnswering([{ status: 401, body: { error: 'invalid_code' } }]);
    const outcome = promptForStepUp(host(), 'Resetting the vault', messageFor);
    type('000000');
    submit();
    await settle();
    let settled = false;
    void outcome.then(() => {
      settled = true;
    });
    await settle();
    expect(settled).toBe(false);
  });

  it('does NOT read a dead SESSION as a wrong code', async () => {
    // THE DEFECT THIS PR CLOSES. `unauthorized` is `SessionGuard` saying the
    // vault session has ended; answering it with "try the current one" told a
    // user to retype a code for as long as they were willing to.
    expect(await refuse(401, 'unauthorized')).toBe('generic:UNAUTHENTICATED');
  });

  it('does NOT read the guessing CAP as a wrong code', async () => {
    expect(await refuse(429, 'too_many_attempts')).toBe('generic:TOO_MANY_ATTEMPTS');
  });

  it('resolves the three refusals to three DIFFERENT codes', async () => {
    // DISCRIMINATION, not coverage: "each renders something" is satisfied by a
    // prompt that renders one thing for all three, which is what it did.
    const seen = [
      await refuse(401, 'invalid_code'),
      await refuse(401, 'unauthorized'),
      await refuse(429, 'too_many_attempts'),
    ];
    expect(seen.every((text) => text.length > 0)).toBe(true);
    expect(new Set(seen).size).toBe(3);
  });

  it('lets a second attempt through after a refusal', async () => {
    serviceAnswering([
      { status: 401, body: { error: 'invalid_code' } },
      { status: 200, body: { mfaLevel: 'stepup' } },
    ]);
    const outcome = promptForStepUp(host(), 'Resetting the vault', messageFor);
    type('000000');
    submit();
    await settle();
    type('123456');
    submit();
    await expect(outcome).resolves.toBe('elevated');
  });

  it('names the action, so the user knows what they are authorising', () => {
    serviceAnswering([{ status: 200, body: {} }]);
    void promptForStepUp(host(), 'Deleting this item', messageFor);
    expect(document.body.textContent).toMatch(/deleting this item needs a fresh identity check/i);
  });

  it('falls back to the shared copy for a failure that is not a bad code', async () => {
    serviceAnswering([{ status: 503, body: { error: 'unavailable' } }]);
    void promptForStepUp(host(), 'Resetting the vault', messageFor);
    type('123456');
    submit();
    await settle();
    expect(document.body.textContent).toContain('generic:UNAVAILABLE');
  });
});
