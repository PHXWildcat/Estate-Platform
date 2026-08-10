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

  it('says what THIS form holds when a code is refused, not "email and password"', async () => {
    // identity answers `invalid_credentials` for a rejected TOTP code exactly as
    // for a rejected password (the M12 defect), so the generic copy would send
    // someone to check credentials this form does not have.
    serviceAnswering([{ status: 401, body: { error: 'invalid_credentials' } }]);
    const outcome = promptForStepUp(host(), 'Resetting the vault', messageFor);
    type('000000');
    submit();
    await settle();
    expect(document.body.textContent).toMatch(/codes last about 30 seconds/i);
    expect(document.body.textContent).not.toMatch(/email/i);
    // And it is still open — a refusal is not a cancel.
    let settled = false;
    void outcome.then(() => {
      settled = true;
    });
    await settle();
    expect(settled).toBe(false);
  });

  it('lets a second attempt through after a refusal', async () => {
    serviceAnswering([
      { status: 401, body: { error: 'invalid_credentials' } },
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
