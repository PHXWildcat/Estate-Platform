import { request, type ApiFailure, type ApiResult } from './api.js';
import { el, field, onClick, onSubmit, replaceChildren } from './dom.js';

/**
 * PROVING A FACTOR ON THIS ORIGIN (M15 review).
 *
 * PR1 widened `POST /v1/auth/stepup` to the `vault` audience with the stated
 * reason that "a vault session must re-prove a factor without a round trip back
 * across the origin boundary" — and then nothing used it, because redemption
 * handed every vault session a step-up for free. That free step-up was the
 * bypass: `POST /v1/vault/reset` is gated on step-up ALONE (a lost vault
 * password cannot be proven), so a stolen 60-second handoff code could
 * crypto-shred the vault. Redemption grants nothing now, and this is the module
 * that pays for the gate instead.
 *
 * The prompt is deliberately IN PLACE rather than a redirect back to Estate:
 * sending the user away to re-open the vault would re-mint a handoff, which is
 * the credential this whole change exists to devalue.
 */

/** Six digits, the only shape identity's CodeSchema accepts. */
const CODE_PATTERN = /^[0-9]{6}$/;

export type StepUpOutcome = 'elevated' | 'cancelled' | 'failed';

export function stepUp(code: string): Promise<ApiResult<unknown>> {
  return request('/api/auth/stepup', { method: 'POST', body: { code } });
}

/**
 * Render a prompt and resolve once the caller may retry — or gave up.
 *
 * Resolves 'elevated' ONLY after identity accepted the code, so a caller can
 * retry the refused action without guessing. Cancel resolves 'cancelled' and
 * the caller must not proceed: a consent ceremony that continues after consent
 * is withdrawn is the M13 round-3 defect, and this is the same shape.
 */
export function promptForStepUp(
  host: HTMLElement,
  what: string,
  messageFor: (code: ApiFailure) => string,
): Promise<StepUpOutcome> {
  return new Promise((resolve) => {
    const note = el('div');
    const code = field({
      id: 'stepup-code',
      label: 'Six-digit code',
      hint: 'From your authenticator app. Codes last about 30 seconds.',
    });
    const submit = el('button', { class: 'button', type: 'submit' }, ['Confirm']);
    const cancel = el('button', { class: 'button-quiet', type: 'button' }, ['Cancel']);
    onClick(cancel, () => resolve('cancelled'));
    const form = el('form', {}, [
      el('p', { class: 'status status-warn' }, [`${what} needs a fresh identity check.`]),
      code.row,
      el('p', {}, [submit, ' ', cancel]),
      note,
    ]);

    onSubmit(form, () => {
      void (async () => {
        const typed = code.input.value.trim();
        if (!CODE_PATTERN.test(typed)) {
          // Refused before the network, so a typo costs no attempt against the
          // account's own rate limit.
          replaceChildren(
            note,
            el('p', { class: 'status status-error' }, ['Enter the six digits.']),
          );
          return;
        }
        submit.setAttribute('disabled', '');
        replaceChildren(note, el('p', { class: 'status' }, ['Checking…']));
        const done = await stepUp(typed).catch(() => ({
          ok: false as const,
          code: 'UNKNOWN' as const,
        }));
        code.input.value = '';
        submit.removeAttribute('disabled');
        if (!done.ok) {
          replaceChildren(
            note,
            el('p', { class: 'status status-error' }, [
              // identity answers `invalid_credentials` for a rejected TOTP code
              // exactly as for a rejected password, so the generic copy would
              // tell someone to check an email and password on a form that has
              // neither — the M12 defect. Say what this form actually holds.
              done.code === 'UNAUTHENTICATED' || done.code === 'INVALID_REQUEST'
                ? 'That code was not accepted. Codes last about 30 seconds — try the current one.'
                : messageFor(done.code),
            ]),
          );
          return;
        }
        resolve('elevated');
      })();
    });

    replaceChildren(host, form);
  });
}
