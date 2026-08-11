/**
 * @jest-environment jsdom
 */

/**
 * THE ONE MODULE THAT MAY RUN CODE IN A PAGE, and what it refuses to promise.
 *
 * `fill-into-page.spec.ts` proves what the injected function does to a document.
 * This proves the CALL: that it names one tab and no frames, that the payload it
 * sends is the credential and nothing else, and that a platform refusal comes
 * back as an outcome rather than a thrown error — the popup may already be
 * closed, and a rejection there is unhandled by construction.
 */
import { fillIntoPage } from '../src/fill-into-page';
import { injectFill } from '../src/inject';

interface Recorded {
  readonly target: unknown;
  readonly func: unknown;
  readonly args: unknown;
}

function installScripting(answer: (injection: Recorded) => unknown): {
  readonly calls: Recorded[];
} {
  const calls: Recorded[] = [];
  Object.defineProperty(globalThis, 'chrome', {
    value: {
      scripting: {
        executeScript: (injection: Recorded) => {
          calls.push(injection);
          return Promise.resolve(answer(injection));
        },
      },
    },
    writable: true,
    configurable: true,
  });
  return { calls };
}

afterEach(() => {
  delete (globalThis as { chrome?: unknown }).chrome;
});

describe('injecting a fill', () => {
  it('names ONE tab, no frames, and sends the credential as an argument', async () => {
    const { calls } = installScripting(() => [
      { frameId: 0, result: { filledUsername: true, filledSecret: true } },
    ]);

    const outcome = await injectFill(7, { username: 'someone', secret: 's3cret' });
    expect(outcome).toEqual({ ok: true, filledUsername: true, filledSecret: true });

    expect(calls).toHaveLength(1);
    const [only] = calls;
    // The TOP frame of one tab. `allFrames` is not declared in `chrome.d.ts` at
    // all — it was measured to return partial results silently — and `frameIds`
    // is unused because this extension cannot enumerate frames.
    expect(only?.target).toEqual({ tabId: 7 });
    expect(JSON.stringify(only?.target)).not.toContain('allFrames');
    expect(JSON.stringify(only?.target)).not.toContain('frameIds');
    // The function is passed by reference for the platform to serialize, and it
    // is the payload module — not a closure written at the call site.
    expect(only?.func).toBe(fillIntoPage);
    // Exactly the credential, and nothing about the tab, the item or the user.
    expect(only?.args).toEqual([{ username: 'someone', secret: 's3cret' }]);
  });

  it('reports a refusal as an outcome, never as a rejection', async () => {
    // "Cannot access contents of the page" is what the platform says when the
    // activeTab grant does not cover the frame — measured in Chrome 151. The
    // popup may already be closed by then, so a rejection would be unhandled.
    installScripting(() => {
      throw new Error('Cannot access contents of the page.');
    });
    await expect(injectFill(7, { username: 'u', secret: 's' })).resolves.toEqual({
      ok: false,
      filledUsername: false,
      filledSecret: false,
    });
  });

  it('treats an empty result array as "it did not run", not as a fill', async () => {
    installScripting(() => []);
    expect(await injectFill(7, { username: 'u', secret: 's' })).toEqual({
      ok: false,
      filledUsername: false,
      filledSecret: false,
    });
  });

  it('carries back a page with no password field as a fill that filled nothing', async () => {
    // The injection RAN — so `ok` is true — and found nothing to fill. Those are
    // different facts and the popup says different things about them.
    installScripting(() => [
      { frameId: 0, result: { filledUsername: false, filledSecret: false } },
    ]);
    expect(await injectFill(7, { username: 'u', secret: 's' })).toEqual({
      ok: true,
      filledUsername: false,
      filledSecret: false,
    });
  });
});
