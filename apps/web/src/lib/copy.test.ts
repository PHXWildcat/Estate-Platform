import { GQL_ERROR_CODES } from '../graphql/client';
import { errorCopy, messageFor, stepUpMessageFor } from './copy';

/**
 * `errorCopy` is a total `Record<GqlFailureCode, string>`, so a code with no
 * wording is a compile error rather than a test failure — that part needs no
 * assertion. What the type cannot say is whether the words are USABLE, and the
 * failure this file exists to catch is a real one: a mapping added to the BFF and
 * the client union, with copy left to the generic fallback, renders every specific
 * refusal as "something went wrong on our side".
 */
describe('failure copy', () => {
  it('never answers a specific refusal with the generic apology', () => {
    for (const code of GQL_ERROR_CODES) {
      expect(messageFor(code)).not.toBe(errorCopy.UNKNOWN);
      expect(messageFor(code).length).toBeGreaterThan(0);
    }
  });

  it.each(['ROLE_ALREADY_GRANTED', 'PERMISSION_ALREADY_GRANTED'] as const)(
    'says what actually happened for %s',
    (code) => {
      // Both are reached by a double click or a retry rather than by a mistake, so
      // the copy states the outcome and offers no remedy — there is nothing to fix.
      expect(messageFor(code)).toMatch(/already/i);
    },
  );

  it('tells someone at the rate cap to WAIT, and never to re-enter the code', () => {
    // M19 PR4 review. The cap is the one refusal whose remedy is time, and it
    // arrives on the same prompts as INVALID_CREDENTIALS — whose step-up wording
    // is "codes change every 30 seconds, enter the current one". After the cap
    // the current one is refused too, so that advice is actively wrong here, and
    // "try again" unqualified would have someone re-entering codes into a bound
    // that counts their attempts.
    for (const message of [
      messageFor('TOO_MANY_ATTEMPTS'),
      stepUpMessageFor('TOO_MANY_ATTEMPTS'),
    ]) {
      expect(message).toMatch(/wait/i);
      expect(message).not.toMatch(/30 seconds/);
      expect(message).not.toMatch(/authenticator/i);
    }
  });

  it('re-words only the credential code on a step-up prompt', () => {
    // The M12 defect: identity answers `invalid_credentials` for a rejected TOTP
    // code exactly as for a rejected password.
    expect(stepUpMessageFor('INVALID_CREDENTIALS')).toMatch(/30 seconds/);
    expect(stepUpMessageFor('INVALID_CREDENTIALS')).not.toBe(errorCopy.INVALID_CREDENTIALS);
    for (const code of GQL_ERROR_CODES) {
      if (code !== 'INVALID_CREDENTIALS') {
        expect(stepUpMessageFor(code)).toBe(errorCopy[code]);
      }
    }
  });
});
