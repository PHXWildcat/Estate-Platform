/**
 * THE STEP-UP CEREMONY ON THE OPERATOR ORIGIN.
 *
 * SIX of this console's thirteen routes are `StepUpGuard`-ed — the review
 * decision, the verification, both stage decisions, the distribution approval
 * and the close — so a console without this is a console that can read a death
 * case and do nothing about it. Seven of the eight on-screen actions go
 * through the ceremony (approve and reject are two buttons over one route);
 * `startReview` is the one that does not, and that is a decision rather than
 * an omission — claiming a case commits to nothing, is undone by rejecting,
 * and the decision that follows it IS gated, so gating the claim would put a
 * factor in front of picking up work. The split is pinned against the real
 * decorators by `apps/services/settlement/test/session-audience.spec.ts`,
 * where it is measured, so these numbers are not a second copy. `POST /api/auth/stepup` is one of the
 * three identity routes the `operator` audience is admitted to, widened in
 * PR3a for exactly this: the vault origin's precedent is that an isolated
 * origin re-proves a factor WITHOUT a round trip back across the boundary,
 * because coming back means minting a fresh handoff — the credential the M15
 * PR4 review devalued on purpose.
 *
 * IT POLLS, AND THAT IS NOT A FLAKE. Identity grants the elevation; SETTLEMENT
 * learns about it by introspecting the token through `HttpSessionVerifier`,
 * which keeps a short-TTL POSITIVE cache (2026-07-23: negatives are never
 * cached so an outage cannot lock anyone out). So for up to one TTL after a
 * genuine step-up the peer still answers from a cached un-elevated session, and
 * a SINGLE-SHOT retry leaves the prompt sitting there doing nothing for a user
 * whose code was accepted — which is exactly the M13 review's finding against
 * the main app. This is the main app's polling shape ported, not the vault
 * origin's single-shot one: the vault origin re-proves a factor to VAULT, which
 * is the service identity's own session state reaches first-hand, and settlement
 * is a peer behind the cache.
 *
 * CANCEL ABORTS THE LOOP, and so does starting a new attempt. A step-up prompt
 * is a CONSENT ceremony, and an action that proceeds after consent is withdrawn
 * is the one thing it must never do (M13 review round 3, measured: a third
 * `GrantRole` landed after Cancel). Here the stakes are a death case: a retry
 * surviving Cancel could approve a review, or confirm a verification, which is
 * the transition that revokes every session a living person holds.
 *
 * `abandon()` ALSO RESTORES THE FORM rather than leaving that to the request it
 * is cancelling. Neither await here carries a timeout, so a stalled identity
 * call would otherwise leave a declined consent form disabled forever, with a
 * reload as the only way out — the protective action must not be contingent on
 * the permissive one finishing.
 */
import { request, type ApiFailure } from './api.js';
import { el, requireElement } from './dom.js';

/**
 * MIRRORED, NOT GUESSED: this must equal `DEFAULT_CACHE_TTL_MS` in
 * `packages/auth-guard/src/verifier.ts`, and `test/step-up.spec.ts` reads that
 * file and asserts it — the compose-parity mechanism, because a browser client
 * cannot import a NestJS package and a number duplicated without a check is a
 * number that drifts.
 */
export const SESSION_CACHE_TTL_MS = 30_000;

/** A little past the TTL, so the last attempt lands after it has certainly expired. */
export const PROPAGATION_BUDGET_MS = SESSION_CACHE_TTL_MS + 5_000;

/** Short enough to feel prompt, long enough not to spin. */
export const RETRY_INTERVAL_MS = 2_000;

/**
 * What a retried action reports back.
 *
 * `applied` — it went through, or failed for a reason the caller has already
 * put on screen, so the prompt is done. `stale` — the server STILL says
 * `stepup_required`, which after a successful elevation means the peer's cache
 * has not caught up.
 */
export type RetryOutcome = 'applied' | 'stale';

export interface StepUpOptions {
  /** Why the check is needed, in this surface's own words. */
  readonly hint: string;
  readonly submitLabel: string;
  readonly onElevated: () => Promise<RetryOutcome>;
  readonly onCancel: () => void;
  /** Distinguishes the field id when more than one prompt could ever exist. */
  readonly idPrefix: string;
  /** Injected in tests; real code uses the wall clock. */
  readonly sleep?: (ms: number) => Promise<void>;
}

/**
 * A rejected TOTP code must not be explained in the vocabulary of a password.
 *
 * Identity answers `invalid_credentials` for a wrong code exactly as for a
 * wrong password (the M12 finding, fixed on three surfaces since), and this
 * form has no password on it. Codes last thirty seconds, which is the fact the
 * person in front of it actually needs.
 */
function stepUpMessage(code: ApiFailure): string {
  switch (code) {
    case 'UNAUTHENTICATED':
      return 'That code was not accepted. Codes change every 30 seconds — check your authenticator and enter the current one.';
    case 'INVALID_REQUEST':
      return 'That code was not accepted. Enter the six digits currently shown in your authenticator.';
    case 'TOO_MANY_ATTEMPTS':
      return 'Too many attempts. Wait a few minutes before trying again — the code itself may have been fine.';
    case 'NETWORK':
    case 'UNAVAILABLE':
      return 'We could not reach Estate to check that code. Nothing has changed — try again in a moment.';
    default:
      return 'We could not confirm it was you. Try again in a moment.';
  }
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/**
 * Build the prompt. The caller decides where it goes; this owns the ceremony.
 */
export function stepUpPrompt(options: StepUpOptions): HTMLFormElement {
  const sleep = options.sleep ?? defaultSleep;
  const codeId = `${options.idPrefix}-stepup-code`;

  const input = el('input', { id: codeId, class: 'input', type: 'text' });
  input.setAttribute('inputmode', 'numeric');
  input.setAttribute('autocomplete', 'one-time-code');
  const submit = el('button', { type: 'submit', class: 'button' }, [options.submitLabel]);
  const cancel = el('button', { type: 'button', class: 'button' }, ['Cancel']);
  const notice = el('p', { class: 'notice', role: 'alert', 'aria-live': 'polite' }, []);

  // ASSOCIATED, not merely adjacent: `htmlFor` is what makes the field
  // reachable by its label to a screen reader and to a test that asks for it by
  // name. The label text is deliberately the same on every prompt in the
  // product — which is exactly why only ONE may ever be open at a time (M15
  // PR3: two identical "Confirm it's you" fields are indistinguishable to a
  // person and to a query), and this console enforces that by construction:
  // there is one `pending` prompt and the actions are withdrawn while it is up.
  const label = el('label', { class: 'label' }, ['Confirm it’s you']);
  label.htmlFor = codeId;

  const form = el('form', { class: 'prompt' }, [
    el('p', { class: 'lede' }, [options.hint]),
    label,
    input,
    el('p', { class: 'actions' }, [submit, cancel]),
    notice,
  ]);

  /**
   * WHICH SUBMISSION OWNS THIS FORM.
   *
   * A counter rather than a boolean, and for the reason the main app's copy
   * records: Cancel restores the form, so a second attempt can start while the
   * first is still in flight, and a boolean cannot tell "nobody owns this any
   * more" from "somebody else does" — the abandoned request would see consent
   * restored by a DIFFERENT submission and run the action twice.
   */
  let attempt = 0;
  let busy = false;

  function say(text: string): void {
    notice.textContent = text;
  }

  function setBusy(value: boolean, caption: string): void {
    busy = value;
    submit.disabled = value;
    submit.textContent = caption;
  }

  function abandon(): void {
    attempt += 1;
    setBusy(false, options.submitLabel);
    options.onCancel();
  }

  cancel.addEventListener('click', (event) => {
    event.preventDefault();
    abandon();
  });

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (busy) return;
    const code = input.value.trim();
    if (!/^\d{6}$/.test(code)) {
      say('Enter the six digits shown in your authenticator.');
      return;
    }
    // Claimed BEFORE the first await, so a double submit cannot interleave.
    attempt += 1;
    const mine = attempt;
    const owns = (): boolean => attempt === mine;

    setBusy(true, 'Checking…');
    say('');
    void (async (): Promise<void> => {
      const elevated = await request<unknown>('/api/auth/stepup', {
        method: 'POST',
        body: { code },
      });
      if (!owns()) return;
      if (!elevated.ok) {
        setBusy(false, options.submitLabel);
        say(stepUpMessage(elevated.code));
        return;
      }

      setBusy(true, 'Applying…');
      const deadline = Date.now() + PROPAGATION_BUDGET_MS;
      for (;;) {
        const outcome = await options.onElevated();
        if (!owns()) return;
        if (outcome === 'applied') {
          setBusy(false, options.submitLabel);
          return;
        }
        if (Date.now() >= deadline) {
          setBusy(false, options.submitLabel);
          say(
            'Your identity check went through, but the settlement service has not caught up yet. Try that action again in a moment.',
          );
          return;
        }
        await sleep(RETRY_INTERVAL_MS);
        // Re-checked AFTER the sleep as well as after each request: Cancel
        // during the wait must stop the loop, not merely the request.
        if (!owns()) return;
      }
    })();
  });

  return form;
}

/** Focus the code field once the prompt is in the document. */
export function focusStepUp(idPrefix: string): void {
  requireElement(`${idPrefix}-stepup-code`).focus();
}
