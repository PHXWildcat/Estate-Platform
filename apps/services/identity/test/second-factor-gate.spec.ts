/**
 * THE GATE'S DECISION, without a database.
 *
 * `factor-enrollment-gate.int.spec.ts` and `webauthn-enrollment-gate.int.spec.ts`
 * drive this against real Postgres, because the PREDICATE is SQL and a fake
 * repo cannot get SQL wrong. What they cannot isolate is the DECISION — how the
 * three inputs (does the account hold a factor, what is the caller's mfa level,
 * how fresh is their step-up) combine — because reaching it there means seeding
 * a database first.
 *
 * The M13 rule is explicit that both layers are owed when a rule exists at two
 * of them, and this is the other one. It also runs where no Postgres exists,
 * which is the configuration identity's coverage floor is calibrated for and
 * the one `ci.yml`'s database-free step measures.
 */
import { ForbiddenException } from '@nestjs/common';
import type { SessionContext } from '@estate/auth-guard';
import type { MfaRepo } from '../src/mfa.repo';
import { SecondFactorGate } from '../src/second-factor-gate';
import { STEPUP_WINDOW_MS } from '../src/stepup';
import type { WebAuthnRepo } from '../src/webauthn.repo';

const NOW = new Date('2026-08-12T12:00:00.000Z');
const USER = 'user-1';

function makeGate(holds: { totp: boolean; passkey: boolean }): SecondFactorGate {
  return new SecondFactorGate(
    { hasVerifiedTotp: (): Promise<boolean> => Promise.resolve(holds.totp) } as unknown as MfaRepo,
    {
      hasCredentials: (): Promise<boolean> => Promise.resolve(holds.passkey),
    } as unknown as WebAuthnRepo,
  );
}

const caller = (
  mfaLevel: SessionContext['mfaLevel'],
  stepupExpiresAt: Date | null,
): Pick<SessionContext, 'mfaLevel' | 'stepupExpiresAt'> => ({ mfaLevel, stepupExpiresAt });

const FRESH = caller('stepup', new Date(NOW.getTime() + STEPUP_WINDOW_MS));
const LAPSED = caller('stepup', new Date(NOW.getTime() - 1));
const NONE = caller('none', null);

describe('holdsVerifiedFactor asks ONE question over both stores', () => {
  it.each([
    ['nothing', { totp: false, passkey: false }, false],
    ['TOTP only', { totp: true, passkey: false }, true],
    ['passkey only', { totp: false, passkey: true }, true],
    ['both', { totp: true, passkey: true }, true],
  ])('%s → %s', async (_name, holds, expected) => {
    expect(await makeGate(holds).holdsVerifiedFactor(USER)).toBe(expected);
  });

  it('does not consult the second store once the first has answered yes', async () => {
    // Not a performance point: the WebAuthn lookup is a second round trip on a
    // path every enrolment takes, and short-circuiting is the reason the cheap
    // question is asked first.
    const passkey = jest.fn().mockResolvedValue(true);
    const gate = new SecondFactorGate(
      { hasVerifiedTotp: (): Promise<boolean> => Promise.resolve(true) } as unknown as MfaRepo,
      { hasCredentials: passkey } as unknown as WebAuthnRepo,
    );
    expect(await gate.holdsVerifiedFactor(USER)).toBe(true);
    expect(passkey).not.toHaveBeenCalled();
  });
});

describe('assertMayAddFactor', () => {
  it('ADMITS the bootstrap: an account with no factor has nothing to prove', async () => {
    // Forced rather than chosen — step-up needs a verified factor, so gating
    // this would make a first factor unreachable forever.
    await expect(
      makeGate({ totp: false, passkey: false }).assertMayAddFactor(USER, NONE, NOW),
    ).resolves.toBeUndefined();
  });

  it.each([
    ['TOTP', { totp: true, passkey: false }],
    ['a passkey', { totp: false, passkey: true }],
    ['both', { totp: true, passkey: true }],
  ])('REFUSES an unproven caller when the account holds %s', async (_name, holds) => {
    await expect(makeGate(holds).assertMayAddFactor(USER, NONE, NOW)).rejects.toThrow(
      ForbiddenException,
    );
    await expect(makeGate(holds).assertMayAddFactor(USER, NONE, NOW)).rejects.toMatchObject({
      response: { error: 'stepup_required' },
    });
  });

  it('ADMITS a caller whose step-up is still fresh', async () => {
    await expect(
      makeGate({ totp: true, passkey: false }).assertMayAddFactor(USER, FRESH, NOW),
    ).resolves.toBeUndefined();
  });

  it('REFUSES a step-up that has LAPSED, not merely one that is absent', async () => {
    // The freshness half. A gate that checked only `mfaLevel === 'stepup'`
    // would admit a session elevated hours ago, which is the whole reason
    // docs/01 §5 puts a five-minute window on it.
    await expect(
      makeGate({ totp: true, passkey: false }).assertMayAddFactor(USER, LAPSED, NOW),
    ).rejects.toMatchObject({ response: { error: 'stepup_required' } });
  });

  it('uses the CALLER’S OWN freshness, evaluated against the clock it is given', async () => {
    // Same session context, two instants: fresh at one, lapsed at the other.
    // A gate reading a clock of its own could disagree with the guard every
    // other route uses.
    const gate = makeGate({ totp: true, passkey: false });
    const justInside = new Date(FRESH.stepupExpiresAt!.getTime() - 1);
    const justOutside = new Date(FRESH.stepupExpiresAt!.getTime() + 1);
    await expect(gate.assertMayAddFactor(USER, FRESH, justInside)).resolves.toBeUndefined();
    await expect(gate.assertMayAddFactor(USER, FRESH, justOutside)).rejects.toMatchObject({
      response: { error: 'stepup_required' },
    });
  });
});
