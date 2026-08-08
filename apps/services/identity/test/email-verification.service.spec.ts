import { BadRequestException } from '@nestjs/common';
import { VERIFICATION_CODE_PATTERN, type NotificationsPort } from '@estate/notifications-client';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import {
  EmailVerificationRepo,
  MAX_VERIFY_ATTEMPTS,
  VerificationRaceError,
} from '../src/email-verification.repo';
import {
  CANONICAL_CODE_LENGTH,
  CODE_RANDOM_BYTES,
  EmailVerificationService,
  REISSUE_FLOOR_MS,
  VERIFICATION_TTL_MS,
  canonicalCode,
} from '../src/email-verification.service';
import type { EventsService } from '../src/events.service';

const USER = 'a1b2c3d4-0000-4000-8000-000000000001';
const OTHER = 'a1b2c3d4-0000-4000-8000-000000000002';
const SESSION = 'a1b2c3d4-0000-4000-8000-0000000000ff';
const NOW = new Date('2026-08-07T12:00:00.000Z');

/**
 * A submission of the right SHAPE but not a real code, so the refusal under
 * test is the lookup's and never the length guard's. Derived from the mint's
 * own constants rather than typed out, because a hand-counted literal that
 * drifted would silently move every case below onto the shape check.
 */
const VALID_SHAPE = `EV1-${'K7MN-'.repeat((CODE_RANDOM_BYTES * 8) / 5 / 4).slice(0, -1)}`;

interface Fakes {
  codes: {
    findLive: jest.Mock;
    lastMintedAt: jest.Mock;
    insert: jest.Mock;
    findByCode: jest.Mock;
    countAttempt: jest.Mock;
    markVerified: jest.Mock;
    revokeLive: jest.Mock;
  };
  authEvents: { insert: jest.Mock };
  events: {
    emailVerificationSent: jest.Mock;
    emailVerified: jest.Mock;
    emailVerificationFailed: jest.Mock;
    emailVerificationUnavailable: jest.Mock;
  };
  notifications: {
    sendAddressVerification: jest.Mock;
    markRecipientVerified: jest.Mock;
    recipientStatus: jest.Mock;
  };
}

function makeFakes(): Fakes {
  return {
    codes: {
      findLive: jest.fn().mockResolvedValue(null),
      lastMintedAt: jest.fn().mockResolvedValue(null),
      insert: jest.fn().mockResolvedValue('code-row-1'),
      findByCode: jest.fn().mockResolvedValue(null),
      countAttempt: jest.fn().mockResolvedValue(undefined),
      markVerified: jest.fn().mockResolvedValue(true),
      revokeLive: jest.fn().mockResolvedValue(true),
    },
    authEvents: { insert: jest.fn() },
    events: {
      emailVerificationSent: jest.fn(),
      emailVerified: jest.fn(),
      emailVerificationFailed: jest.fn(),
      emailVerificationUnavailable: jest.fn(),
    },
    notifications: {
      sendAddressVerification: jest.fn().mockResolvedValue({
        accepted: true,
        delivered: true,
        channel: 'email',
      }),
      markRecipientVerified: jest.fn().mockResolvedValue({ ok: true }),
      recipientStatus: jest.fn().mockResolvedValue({ verified: false }),
    },
  };
}

function makeService(fakes: Fakes): EmailVerificationService {
  return new EmailVerificationService(
    fakes.codes as unknown as EmailVerificationRepo,
    fakes.authEvents as unknown as AuthEventsRepo,
    fakes.events as unknown as EventsService,
    fakes.notifications as unknown as NotificationsPort,
    () => NOW,
  );
}

/** One recorded call's first argument, typed rather than `any`-walked. */
function firstArg<T>(mock: jest.Mock): T {
  return (mock.mock.calls as unknown[][])[0]?.[0] as T;
}

/** The code as the notifications client actually received it. */
function mailedCode(fakes: Fakes): string {
  return firstArg<{ code: string }>(fakes.notifications.sendAddressVerification).code;
}

describe('the minted code', () => {
  it('derives its width rather than asserting it — 160 bits, 32 base32 characters', () => {
    const fakes = makeFakes();
    const service = makeService(fakes);
    return service.ensureVerificationRequested(USER).then(() => {
      const code = mailedCode(fakes);
      // THE WIDTH IS THE SECURITY PARAMETER, so it is measured against a real
      // mint. M6's grantee fingerprint shipped 50 bits where its spec said 80
      // and M13's first link code mapped one character per BYTE for a real
      // width of 100; both were found by looking at what a running system
      // produced, which is what this does.
      expect(code.startsWith('EV1-')).toBe(true);
      expect(code.replace(/^EV1-/, '').replace(/-/g, '')).toHaveLength((CODE_RANDOM_BYTES * 8) / 5);
      expect(canonicalCode(code)).toHaveLength(CANONICAL_CODE_LENGTH);
    });
  });

  it('draws its body from an alphabet with no I, L, O or U', async () => {
    // The alphabet exists so a code survives being read off a screen and
    // retyped. If the generator emitted an ambiguous character, the canonical
    // fold would rewrite it and the round trip would silently break.
    const fakes = makeFakes();
    for (let i = 0; i < 25; i += 1) {
      fakes.notifications.sendAddressVerification.mockClear();
      await makeService(fakes).ensureVerificationRequested(USER);
      const body = mailedCode(fakes).replace(/^EV1-/, '').replace(/-/g, '');
      expect(body).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]+$/);
    }
  });

  it('satisfies the WIRE pattern the notifications service validates against', async () => {
    // The M14 review found the two ends disagreeing: notifications accepted
    // `/^[0-9A-Z-]+$/` up to 64 characters while this mints Crockford base32,
    // so the route would take 64 characters of readable English and interpolate
    // it into a real message. The pattern is one shared declaration now, and
    // this is the assertion that makes a change to EITHER end fail a test
    // rather than silently widen what the platform may mail.
    const fakes = makeFakes();
    for (let i = 0; i < 25; i += 1) {
      fakes.notifications.sendAddressVerification.mockClear();
      await makeService(fakes).ensureVerificationRequested(USER);
      expect(mailedCode(fakes)).toMatch(VERIFICATION_CODE_PATTERN);
    }
  });

  it('never mints the same code twice', async () => {
    const fakes = makeFakes();
    const seen = new Set<string>();
    for (let i = 0; i < 25; i += 1) {
      fakes.notifications.sendAddressVerification.mockClear();
      await makeService(fakes).ensureVerificationRequested(USER);
      seen.add(mailedCode(fakes));
    }
    expect(seen.size).toBe(25);
  });
});

describe('canonicalCode', () => {
  it('folds exactly what a human retyping a code gets wrong', () => {
    // Lowercase, a typed O for zero, an I or L for one, dropped grouping
    // dashes, a stray space. The M13 review found this fold missing on the
    // redemption side, so the very confusions the alphabet exists to survive
    // all failed with the uniform refusal.
    expect(canonicalCode('ev1-k7mn')).toBe(canonicalCode('EV1-K7MN'));
    expect(canonicalCode('EV1 K7MN')).toBe(canonicalCode('EV1-K7MN'));
    expect(canonicalCode('EV1-K7MN')).toBe(canonicalCode('EV1K7MN'));
    expect(canonicalCode('O0O')).toBe('000');
    expect(canonicalCode('IL1')).toBe('111');
  });

  it('is INJECTIVE on minted codes, so folding cannot make two codes collide', async () => {
    // The prefix folds identically for every code and so distinguishes
    // nothing; within the body — drawn from an alphabet without I, L, O or U —
    // the fold is the identity. Asserted against real mints rather than argued.
    const fakes = makeFakes();
    const folded = new Set<string>();
    for (let i = 0; i < 50; i += 1) {
      fakes.notifications.sendAddressVerification.mockClear();
      await makeService(fakes).ensureVerificationRequested(USER);
      const code = mailedCode(fakes);
      folded.add(canonicalCode(code));
      // Identity on the body.
      const body = code.replace(/^EV1-/, '').replace(/-/g, '');
      expect(canonicalCode(code).endsWith(body)).toBe(true);
    }
    expect(folded.size).toBe(50);
  });
});

describe('ensureVerificationRequested (the login hook)', () => {
  it('mints and mails when the address is unverified and no code is live', async () => {
    const fakes = makeFakes();
    await makeService(fakes).ensureVerificationRequested(USER);

    expect(fakes.codes.insert).toHaveBeenCalledTimes(1);
    expect(fakes.notifications.sendAddressVerification).toHaveBeenCalledTimes(1);
    // Only the DIGEST is stored — a database read must not yield a usable code.
    const stored = firstArg<{ codeSha256: Buffer; expiresAt: Date }>(fakes.codes.insert);
    expect(stored.codeSha256).toHaveLength(32);
    expect(stored.codeSha256.toString('utf8')).not.toContain('EV1');
    expect(stored.expiresAt.getTime()).toBe(NOW.getTime() + VERIFICATION_TTL_MS);
  });

  it('does NOTHING when the address is already verified', async () => {
    const fakes = makeFakes();
    fakes.notifications.recipientStatus.mockResolvedValue({ verified: true });
    await makeService(fakes).ensureVerificationRequested(USER);
    expect(fakes.codes.insert).not.toHaveBeenCalled();
    expect(fakes.notifications.sendAddressVerification).not.toHaveBeenCalled();
  });

  it('does NOTHING when the status query is unanswerable', async () => {
    // A notifications service we cannot reach cannot mail the code either, so
    // minting would burn the user's one live code on a send about to fail. It
    // self-heals at the next login.
    const fakes = makeFakes();
    fakes.notifications.recipientStatus.mockResolvedValue(null);
    await makeService(fakes).ensureVerificationRequested(USER);
    expect(fakes.codes.insert).not.toHaveBeenCalled();
  });

  it('IS IDEMPOTENT: a live code inside the floor mints nothing', async () => {
    // Without this, every login mails another code — an escalating annoyance
    // for the user and, for an account standing on somebody else's address,
    // an unbounded one for a stranger. It is the only rate limit on this path.
    const fakes = makeFakes();
    fakes.codes.lastMintedAt.mockResolvedValue(new Date(NOW.getTime() - REISSUE_FLOOR_MS + 1000));
    fakes.codes.findLive.mockResolvedValue({
      createdAt: new Date(NOW.getTime() - REISSUE_FLOOR_MS + 1000),
    });
    await makeService(fakes).ensureVerificationRequested(USER);
    expect(fakes.codes.insert).not.toHaveBeenCalled();
    expect(fakes.notifications.sendAddressVerification).not.toHaveBeenCalled();
  });

  it("RE-MINTS after a code lapses — the M14 review's worst finding, pinned", async () => {
    // The partial unique index cannot carry an expiry predicate, so a lapsed
    // row still occupies the live slot. Retiring only when `findLive` saw a row
    // meant nothing ever cleared it: the insert took the unique violation and
    // this answered `too_soon` FOREVER, permanently locking the account out of
    // verification and out of every M14 arming gate. Ignoring the first email
    // was enough to trigger it.
    //
    // `findLive` sees nothing (lapsed) while a row still occupies the index —
    // exactly the state that used to wedge.
    const fakes = makeFakes();
    fakes.codes.findLive.mockResolvedValue(null);
    fakes.codes.lastMintedAt.mockResolvedValue(new Date(NOW.getTime() - REISSUE_FLOOR_MS - 1000));
    fakes.codes.revokeLive.mockResolvedValue(true);

    await makeService(fakes).ensureVerificationRequested(USER);

    // It RETIRED the lapsed row before minting...
    expect(fakes.codes.revokeLive).toHaveBeenCalledWith(USER, NOW);
    // ...and actually minted and mailed a new code.
    expect(fakes.codes.insert).toHaveBeenCalledTimes(1);
    expect(fakes.notifications.sendAddressVerification).toHaveBeenCalledTimes(1);
    // No retirement is AUDITED, because nothing usable was retired — a lapsed
    // code had already stopped working.
    expect(
      (fakes.authEvents.insert.mock.calls as { kind: string }[][]).map((call) => call[0]?.kind),
    ).not.toContain('email_verification.reissued');
  });

  it('applies the floor even when NO live code exists — the resend loop, closed', async () => {
    // A send that fails RETIRES its code, so the old floor (checked only when a
    // live code existed) was skipped in exactly the state where sends were
    // failing: the resend route then had no rate limit at all, and each
    // iteration cost a real SES call and two append-only auth_events rows.
    const fakes = makeFakes();
    fakes.codes.findLive.mockResolvedValue(null);
    fakes.codes.lastMintedAt.mockResolvedValue(new Date(NOW.getTime() - 1000));

    expect(await makeService(fakes).reissue(USER)).toBe('too_soon');
    expect(fakes.codes.insert).not.toHaveBeenCalled();
    expect(fakes.notifications.sendAddressVerification).not.toHaveBeenCalled();
  });

  it('re-mints once the floor has passed, RETIRING the previous code first', async () => {
    // Exactly one code is ever usable, so a code the user gave up on cannot be
    // redeemed later by whoever else saw it.
    const fakes = makeFakes();
    fakes.codes.lastMintedAt.mockResolvedValue(new Date(NOW.getTime() - REISSUE_FLOOR_MS - 1000));
    fakes.codes.findLive.mockResolvedValue({
      createdAt: new Date(NOW.getTime() - REISSUE_FLOOR_MS - 1000),
    });
    await makeService(fakes).ensureVerificationRequested(USER);
    expect(fakes.codes.revokeLive).toHaveBeenCalledWith(USER, NOW);
    expect(fakes.codes.insert).toHaveBeenCalledTimes(1);
    expect(
      (fakes.authEvents.insert.mock.calls as { kind: string }[][]).map((call) => call[0]?.kind),
    ).toContain('email_verification.reissued');
  });

  it('RETIRES a code whose mail never left, so the next login can try again', async () => {
    // Otherwise the idempotence guard turns into a lockout: it would refuse to
    // mint for a full TTL over a mail that does not exist.
    const fakes = makeFakes();
    fakes.notifications.sendAddressVerification.mockResolvedValue({ accepted: false });
    await makeService(fakes).ensureVerificationRequested(USER);
    expect(fakes.codes.revokeLive).toHaveBeenCalledWith(USER, NOW);
    expect(fakes.events.emailVerificationSent).toHaveBeenCalledWith(USER, false);
  });

  it('treats a lost mint race as success by somebody else', async () => {
    const fakes = makeFakes();
    fakes.codes.insert.mockRejectedValue(new VerificationRaceError());
    await expect(makeService(fakes).ensureVerificationRequested(USER)).resolves.toBeUndefined();
    expect(fakes.notifications.sendAddressVerification).not.toHaveBeenCalled();
  });

  it('NEVER throws into the auth path', async () => {
    // It is fire-and-forget at the call site; a login that failed because SES
    // was down would be strictly worse than an unverified address.
    const fakes = makeFakes();
    fakes.notifications.recipientStatus.mockRejectedValue(new Error('boom'));
    await expect(makeService(fakes).ensureVerificationRequested(USER)).resolves.toBeUndefined();

    const throwing = makeFakes();
    throwing.codes.insert.mockRejectedValue(new Error('db down'));
    await expect(makeService(throwing).ensureVerificationRequested(USER)).resolves.toBeUndefined();
  });
});

describe('reissue (the user asked for another code)', () => {
  it('reports each outcome honestly rather than always claiming a send', async () => {
    const verified = makeFakes();
    verified.notifications.recipientStatus.mockResolvedValue({ verified: true });
    expect(await makeService(verified).reissue(USER)).toBe('already_verified');

    const down = makeFakes();
    down.notifications.recipientStatus.mockResolvedValue(null);
    expect(await makeService(down).reissue(USER)).toBe('unavailable');

    const tooSoon = makeFakes();
    tooSoon.codes.lastMintedAt.mockResolvedValue(NOW);
    tooSoon.codes.findLive.mockResolvedValue({ createdAt: NOW });
    expect(await makeService(tooSoon).reissue(USER)).toBe('too_soon');

    const ok = makeFakes();
    expect(await makeService(ok).reissue(USER)).toBe('sent');

    const undelivered = makeFakes();
    undelivered.notifications.sendAddressVerification.mockResolvedValue({ accepted: false });
    expect(await makeService(undelivered).reissue(USER)).toBe('unavailable');
  });
});

describe('verify', () => {
  const liveRow = {
    id: 'code-row-1',
    user_id: USER,
    expires_at: new Date(NOW.getTime() + 60_000),
    attempts: 0,
    revoked_at: null,
    verified_at: null,
  };

  it('spends the code, then vouches — the irreversible step runs LAST', async () => {
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue(liveRow);
    await makeService(fakes).verify(USER, SESSION, VALID_SHAPE);

    expect(fakes.codes.markVerified).toHaveBeenCalledWith('code-row-1', NOW);
    expect(fakes.notifications.markRecipientVerified).toHaveBeenCalledWith({ userId: USER });
    expect(fakes.events.emailVerified).toHaveBeenCalledWith(USER, SESSION);
  });

  it('hashes the CANONICAL form, so a retyped code still works', async () => {
    const fakes = makeFakes();
    const minted = await (async (): Promise<string> => {
      await makeService(fakes).ensureVerificationRequested(USER);
      return mailedCode(fakes);
    })();
    const digest = firstArg<{ codeSha256: Buffer }>(fakes.codes.insert).codeSha256;

    const verifier = makeFakes();
    verifier.codes.findByCode.mockResolvedValue(liveRow);
    await makeService(verifier).verify(USER, SESSION, minted.toLowerCase().replace(/-/g, ''));
    expect(firstArg<Buffer>(verifier.codes.findByCode).equals(digest)).toBe(true);
  });

  it.each([
    ['unknown', null],
    ['spent', { ...liveRow, verified_at: NOW }],
    ['revoked', { ...liveRow, revoked_at: NOW }],
    ['expired', { ...liveRow, expires_at: new Date(NOW.getTime() - 1) }],
    ['attempt-exhausted', { ...liveRow, attempts: MAX_VERIFY_ATTEMPTS }],
    ["somebody else's", { ...liveRow, user_id: OTHER }],
  ])('refuses a %s code with the SAME uniform answer', async (_label, row) => {
    // Distinguishing them would tell whoever holds a guess that their guess
    // named something real (M13's rule, restated for this ceremony).
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue(row);
    await expect(makeService(fakes).verify(USER, SESSION, VALID_SHAPE)).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    expect(fakes.notifications.markRecipientVerified).not.toHaveBeenCalled();
  });

  it('measures length on the CANONICAL form, and refuses before any lookup', async () => {
    // A body of nothing but separators satisfies a raw length check and folds
    // to the empty string — the M13 round-3 finding, avoided rather than
    // repeated.
    const fakes = makeFakes();
    await expect(makeService(fakes).verify(USER, SESSION, '--------')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.codes.findByCode).not.toHaveBeenCalled();
    expect(fakes.events.emailVerificationFailed).toHaveBeenCalled();
  });

  it("never counts an attempt against somebody else's code", async () => {
    // Keyed on the CALLER, so a signed-in attacker who somehow resolved another
    // user's digest still cannot exhaust that victim's attempts.
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue({ ...liveRow, user_id: OTHER });
    await expect(makeService(fakes).verify(USER, SESSION, VALID_SHAPE)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.codes.countAttempt).toHaveBeenCalledWith(USER, NOW);
    expect(fakes.codes.countAttempt).not.toHaveBeenCalledWith(OTHER, expect.anything());
  });

  it('counts a WRONG GUESS, which resolves to no row at all', async () => {
    // The case the old cap could never see. A wrong code produces a DIFFERENT
    // DIGEST, so the lookup returns nothing — and the previous implementation
    // took a resolved row id, so it never moved a counter for the only kind of
    // failure a guesser actually produces. Round 2 of the M14 review found the
    // cap decorative because of exactly this.
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue(null);
    await expect(makeService(fakes).verify(USER, SESSION, VALID_SHAPE)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.codes.countAttempt).toHaveBeenCalledWith(USER, NOW);
  });

  it('refuses when the delivery store has no live row to vouch for', async () => {
    // "Your address is verified" about an address the store cannot reach is the
    // exact false assurance this milestone exists to remove.
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue(liveRow);
    fakes.notifications.markRecipientVerified.mockResolvedValue({ ok: false });
    await expect(makeService(fakes).verify(USER, SESSION, VALID_SHAPE)).rejects.toMatchObject({
      response: { error: 'verification_unavailable' },
    });
    expect(fakes.events.emailVerified).not.toHaveBeenCalled();
    // RECORDED AS AN OUTAGE, NOT AS A FAILED VERIFICATION. Round 2 of this
    // review found the fix shipped with only the two assertions above, both of
    // which held BEFORE it — so nothing would have gone red on a revert, in a
    // commit that claimed every fix was mutation-tested. The whole point of the
    // change is which action lands in which trail, so that is what is asserted.
    expect(fakes.events.emailVerificationUnavailable).toHaveBeenCalledWith(USER, SESSION);
    expect(fakes.events.emailVerificationFailed).not.toHaveBeenCalled();
  });

  it('refuses when a concurrent redemption already spent the code', async () => {
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue(liveRow);
    fakes.codes.markVerified.mockResolvedValue(false);
    await expect(makeService(fakes).verify(USER, SESSION, VALID_SHAPE)).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    expect(fakes.notifications.markRecipientVerified).not.toHaveBeenCalled();
  });

  it('records failures with NO reason — the trail must not re-create the oracle', async () => {
    const fakes = makeFakes();
    fakes.codes.findByCode.mockResolvedValue(null);
    await expect(makeService(fakes).verify(USER, SESSION, VALID_SHAPE)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(fakes.events.emailVerificationFailed).toHaveBeenCalledWith(USER, SESSION);
    const kinds = (fakes.authEvents.insert.mock.calls as unknown[][]).map((call) => call[0]);
    expect(kinds).toEqual([
      { userId: USER, sessionId: SESSION, kind: 'email_verification.failed' },
    ]);
  });
});
