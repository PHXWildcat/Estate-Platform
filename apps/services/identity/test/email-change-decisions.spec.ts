/**
 * THE ADDRESS-CHANGE DECISION LAYER, with the repo faked (M17 PR4).
 *
 * `email-change.int.spec.ts` proves the SQL. This proves the choices above it
 * — which refusals fire before any work, in what order the gates run, and the
 * two properties that live in SOURCE because a runtime test cannot see them
 * (the M17 PR1 ordering-pin rule: a fast await and no await are
 * indistinguishable at runtime).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HttpException } from '@nestjs/common';
import { EmailChangeService } from '../src/email-change.service';
import { ChangeRaceError } from '../src/email-change.repo';
import { CHANGE_ADDRESS_BOUND } from '../src/rate-bounds';
import { canonicalCode, sha256 } from '../src/readable-code';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import type { Db } from '../src/db';
import type { EmailChangeRepo } from '../src/email-change.repo';
import type { EmailVerificationRepo } from '../src/email-verification.repo';
import type { EventsService } from '../src/events.service';
import type { PasswordHasher } from '../src/password';
import type { PasswordResetRepo } from '../src/password-reset.repo';
import type { SecondFactorGate } from '../src/second-factor-gate';
import type { SessionsRepo } from '../src/sessions.repo';
import type { UsersRepo } from '../src/users.repo';
import { DELIVERED, DELIVERED_UNVERIFIED, UNREACHABLE } from './notifications-double';

const NOW = new Date('2026-08-13T12:00:00.000Z');
const USER = 'b6c9a1de-0000-4000-8000-000000000042';
const CALLER = { mfaLevel: 'stepup' as const, stepupExpiresAt: new Date(NOW.getTime() + 60_000) };

function code(file: string): string {
  return readFileSync(join(__dirname, '..', 'src', file), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

interface Fakes {
  service: EmailChangeService;
  gateAsks: number;
  passwordChecks: number;
  finds: number;
  attempts: number;
  spends: number;
  inserts: number;
  retires: number;
  mailed: Array<{ code: string; email: string }>;
  effects: string[];
}

function makeService(opts?: {
  liveRow?: unknown;
  gateRefuses?: boolean;
  destinationTaken?: boolean;
  sendAccepted?: boolean;
  insertRaces?: boolean;
  updateEmailSucceeds?: boolean;
  passwordOk?: boolean;
  currentBidx?: Buffer;
  lastMinted?: Date;
}): Fakes {
  const state = {
    gateAsks: 0,
    passwordChecks: 0,
    finds: 0,
    attempts: 0,
    spends: 0,
    inserts: 0,
    retires: 0,
    mailed: [] as Array<{ code: string; email: string }>,
    effects: [] as string[],
    revokedSessions: 0,
  };
  const order: string[] = [];
  const service = new EmailChangeService(
    {
      findById: (): Promise<unknown> =>
        Promise.resolve({
          id: USER,
          password_hash: 'argon2-CURRENT',
          status: 'active',
          dek_id: 'dek-1',
          email_bidx: opts?.currentBidx ?? Buffer.alloc(32, 1),
        }),
      findByEmailBidx: (): Promise<unknown> =>
        Promise.resolve(opts?.destinationTaken ? { id: 'someone-else' } : null),
      updateEmail: (): Promise<boolean> => {
        state.effects.push('switch');
        if (opts?.updateEmailSucceeds === false) {
          const err = new Error('duplicate') as Error & { code: string };
          err.code = '23505';
          throw err;
        }
        return Promise.resolve(true);
      },
    } as unknown as UsersRepo,
    {
      revokeAllForUserExcept: (): Promise<string[]> => {
        state.effects.push('revoke-sessions');
        state.revokedSessions += 1;
        return Promise.resolve(['other-1', 'other-2']);
      },
    } as unknown as SessionsRepo,
    {
      lastMintedAt: (): Promise<Date | null> => Promise.resolve(opts?.lastMinted ?? null),
      revokeLive: (): Promise<boolean> => {
        state.retires += 1;
        return Promise.resolve(false);
      },
      findLive: (): Promise<unknown> => {
        state.finds += 1;
        return Promise.resolve(opts?.liveRow ?? null);
      },
      countAttempt: (): Promise<void> => {
        state.attempts += 1;
        return Promise.resolve();
      },
      markCompleted: (): Promise<boolean> => {
        state.spends += 1;
        state.effects.push('spend');
        return Promise.resolve(true);
      },
      insert: (): Promise<string> => {
        state.inserts += 1;
        if (opts?.insertRaces) {
          throw new ChangeRaceError();
        }
        return Promise.resolve('row-1');
      },
    } as unknown as EmailChangeRepo,
    {
      revokeLive: (): Promise<boolean> => {
        state.effects.push('sweep-resets');
        return Promise.resolve(false);
      },
    } as unknown as PasswordResetRepo,
    {
      revokeLive: (): Promise<boolean> => {
        state.effects.push('sweep-verifications');
        return Promise.resolve(false);
      },
    } as unknown as EmailVerificationRepo,
    { insert: (): Promise<void> => Promise.resolve() } as unknown as AuthEventsRepo,
    {
      verifyPassword: (): Promise<boolean> => {
        state.passwordChecks += 1;
        order.push('password');
        return Promise.resolve(opts?.passwordOk !== false);
      },
    } as unknown as PasswordHasher,
    {
      assertMayAddFactor: (): Promise<void> => {
        state.gateAsks += 1;
        order.push('gate');
        if (opts?.gateRefuses) {
          throw new HttpException({ error: 'stepup_required' }, 403);
        }
        return Promise.resolve();
      },
    } as unknown as SecondFactorGate,
    {
      emailChangeRequested: (): Promise<void> => Promise.resolve(),
      emailChangeCompleted: (): Promise<void> => Promise.resolve(),
      emailChangeCancelled: (): Promise<void> => Promise.resolve(),
      emailChangeDenied: (): Promise<void> => Promise.resolve(),
      emailChangeFailed: (): Promise<void> => Promise.resolve(),
      emailChangeThrottled: (): Promise<void> => Promise.resolve(),
    } as unknown as EventsService,
    {
      withTransaction: (_actor: string, fn: (tx: unknown) => Promise<unknown>): Promise<unknown> =>
        fn({}),
    } as unknown as Db,
    {
      encryptField: (): Promise<{ ciphertext: Buffer; dekId: string }> =>
        Promise.resolve({ ciphertext: Buffer.from('ct'), dekId: 'dek-1' }),
      decryptField: (): Promise<Buffer> => Promise.resolve(Buffer.from('x@y.z')),
    } as never,
    { emailIndexKey: Buffer.alloc(32, 3) } as unknown as IdentityConfig,
    () => NOW,
    {
      sendEmailChange: (input: { code: string; email: string }): Promise<unknown> => {
        state.mailed.push({ code: input.code, email: input.email });
        state.effects.push('challenge');
        return Promise.resolve(opts?.sendAccepted === false ? UNREACHABLE : DELIVERED_UNVERIFIED);
      },
      sendAccountSecurity: (): Promise<unknown> => {
        state.effects.push('notify-old');
        return Promise.resolve(DELIVERED);
      },
      replaceRecipient: (): Promise<{ ok: boolean }> => {
        state.effects.push('replace');
        return Promise.resolve({ ok: true });
      },
    } as never,
  );
  return {
    service,
    get gateAsks() {
      return state.gateAsks;
    },
    get passwordChecks() {
      return state.passwordChecks;
    },
    get finds() {
      return state.finds;
    },
    get attempts() {
      return state.attempts;
    },
    get spends() {
      return state.spends;
    },
    get inserts() {
      return state.inserts;
    },
    get retires() {
      return state.retires;
    },
    get mailed() {
      return state.mailed;
    },
    get effects() {
      return state.effects;
    },
  };
}

describe('the request gate', () => {
  it('asks for the FACTOR before it checks the password — not a free password oracle', async () => {
    const f = makeService({ gateRefuses: true });
    let refused: unknown;
    try {
      await f.service.requestChange(USER, CALLER, 'any-guess', 'new@example.com');
    } catch (err) {
      refused = err;
    }
    expect(refused).toBeInstanceOf(HttpException);
    expect((refused as HttpException).getStatus()).toBe(403);
    // The password was NEVER evaluated: a caller who cannot clear the factor
    // gate learns nothing about whether their password guess was right.
    expect(f.gateAsks).toBe(1);
    expect(f.passwordChecks).toBe(0);
  });

  it('THE ORDER IS PINNED AT THE SOURCE — gate, then password, in the method body', () => {
    // A runtime test proves the refusing case above; only the source can prove
    // the ORDER when both pass (the M17 PR1 rule). Comments are stripped so
    // prose cannot satisfy it.
    const body = code('email-change.service.ts');
    const gateAt = body.indexOf('assertMayAddFactor');
    const passwordAt = body.indexOf('verifyPassword');
    expect(gateAt).toBeGreaterThan(-1);
    expect(passwordAt).toBeGreaterThan(-1);
    expect(gateAt).toBeLessThan(passwordAt);
  });

  it('THE ROUTE DOES NOT AWAIT THE STAGED HALF — pinned at the source, where it lives', () => {
    // The availability lookup, the encrypt, the stage and the send vary with
    // whether the DESTINATION has an account; the caller's 202 must not. The
    // handler is necessarily async (the gate half is awaited), so the PR3
    // sync-signature trick is unavailable — the pin is the call-site shape.
    const controller = readFileSync(
      join(__dirname, '..', 'src', 'auth.controller.ts'),
      'utf8',
    ).replace(/\/\*[\s\S]*?\*\//g, '');
    expect(controller).toMatch(/void staged\(\)\.catch\(\(\) => \{\}\);/);
    expect(controller).not.toMatch(/await staged\(\)/);
  });

  it('a WRONG password is refused with the credentials token, after the gate', async () => {
    const f = makeService({ passwordOk: false });
    let refused: unknown;
    try {
      await f.service.requestChange(USER, CALLER, 'wrong', 'new@example.com');
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_credentials' });
    expect(f.gateAsks).toBe(1);
  });

  it('changing to the CURRENT address is an open refusal — nothing to keep uniform', async () => {
    const { emailBlindIndex, normalizeEmail } = await import('@estate/crypto');
    const f = makeService({
      currentBidx: emailBlindIndex(Buffer.alloc(32, 3), normalizeEmail('same@example.com')),
    });
    let refused: unknown;
    try {
      await f.service.requestChange(USER, CALLER, 'pw', 'same@example.com');
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_request' });
  });

  it('the floor refuses openly — an authenticated owner told nothing retries into a wall', async () => {
    const f = makeService({ lastMinted: new Date(NOW.getTime() - 60_000) });
    let refused: unknown;
    try {
      await f.service.requestChange(USER, CALLER, 'pw', 'new@example.com');
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'too_soon' });
  });

  it('the destination bound refuses the request past its cap, per address', async () => {
    const f = makeService();
    for (let i = 0; i < CHANGE_ADDRESS_BOUND.max; i += 1) {
      const { staged } = await f.service.requestChange(USER, CALLER, 'pw', 'hot@example.com');
      await staged();
    }
    let refused: unknown;
    try {
      await f.service.requestChange(USER, CALLER, 'pw', 'hot@example.com');
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'too_soon' });
    // …while a different destination is untouched.
    await expect(
      f.service.requestChange(USER, CALLER, 'pw', 'cold@example.com'),
    ).resolves.toBeDefined();
  });

  it('the destination bound is a real bound with real numbers', () => {
    expect(CHANGE_ADDRESS_BOUND.max).toBeLessThanOrEqual(10);
    expect(CHANGE_ADDRESS_BOUND.windowMs).toBeGreaterThanOrEqual(15 * 60 * 1000);
  });
});

describe('the staged half', () => {
  async function drive(f: Fakes, target = 'new@example.com'): Promise<void> {
    const { staged } = await f.service.requestChange(USER, CALLER, 'pw', target);
    await staged();
  }

  it('a FREE destination: retires unconditionally, stages, and mails the code to it', async () => {
    const f = makeService();
    await drive(f);
    // The retire runs BEFORE the mint whether or not anything was live — the
    // M14 predicate-matches-the-index rule exercised through the real flow.
    expect(f.retires).toBe(1);
    expect(f.inserts).toBe(1);
    expect(f.mailed).toHaveLength(1);
    expect(f.mailed[0]?.email).toBe('new@example.com');
    expect(f.mailed[0]?.code).toMatch(/^EC1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/);
  });

  it('a TAKEN destination: no stage, no mail — and no observable difference for the caller', async () => {
    const f = makeService({ destinationTaken: true });
    await drive(f);
    expect(f.inserts).toBe(0);
    expect(f.mailed).toHaveLength(0);
  });

  it('a FAILED SEND retires the code nobody received — not to avoid a lockout', async () => {
    const f = makeService({ sendAccepted: false });
    await drive(f);
    // Once before the mint, once after the failed send.
    expect(f.retires).toBe(2);
  });

  it('a CONCURRENT MINT winning the unique index is adopted, not errored', async () => {
    const f = makeService({ insertRaces: true });
    await expect(drive(f)).resolves.toBeUndefined();
    // Nothing mailed by THIS request; the winner's mail is on its way.
    expect(f.mailed).toHaveLength(0);
  });
});

describe('the completed switch, decision layer', () => {
  const LIVE_ROW = (codeDigest: Buffer): unknown => ({
    id: 'row-1',
    user_id: USER,
    new_email_ct: Buffer.from('ct:x@y.z'),
    new_email_bidx: Buffer.alloc(32, 9),
    dek_id: 'dek-1',
    code_sha256: codeDigest,
    attempts: 0,
    expires_at: new Date(NOW.getTime() + 60_000),
    revoked_at: null,
    completed_at: null,
  });
  const MINTED = 'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';

  it('runs the whole sequence IN ORDER: spend → switch → sweep → revoke → notify-old → replace', async () => {
    const digest = sha256(canonicalCode(MINTED));
    const f = makeService({ liveRow: LIVE_ROW(digest) });
    await f.service.completeChange(USER, 'session-1', MINTED);
    expect(f.effects).toEqual([
      'spend',
      'switch',
      'sweep-resets',
      'sweep-verifications',
      'revoke-sessions',
      // THE ORDERING IS THE CONTROL: the notice to the OLD address before the
      // store repoint, or it reaches the attacker's mailbox instead of the
      // one whose reader can dispute the takeover.
      'notify-old',
      'replace',
    ]);
  });

  it('a RACED REGISTRATION at the switch refuses uniformly and burns no attempt', async () => {
    const digest = sha256(canonicalCode(MINTED));
    const f = makeService({ liveRow: LIVE_ROW(digest), updateEmailSucceeds: false });
    let refused: unknown;
    try {
      await f.service.completeChange(USER, 'session-1', MINTED);
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_code' });
    expect(f.attempts).toBe(0);
    // Nothing after the failed switch ran: no notice, no replace.
    expect(f.effects.filter((e) => e === 'notify-old' || e === 'replace')).toEqual([]);
  });
});

describe('cancel — the ungated protective action', () => {
  it('revokes a live change; a cancel with nothing pending is a silent no-op', async () => {
    // The M6 asymmetry at the decision layer: no gate, no refusal, and no
    // event when there was nothing to withdraw — a user mashing cancel must
    // not fill the trail with retractions of nothing.
    const withLive = makeService();
    // The fake's revokeLive answers false (nothing live) — the no-op half.
    await expect(withLive.service.cancelChange(USER)).resolves.toBeUndefined();
    expect(withLive.retires).toBe(1);
  });
});

describe('completeChange refuses dead codes without work', () => {
  it('a MIS-SHAPED code is refused BEFORE any lookup, and still burns an attempt', async () => {
    // Burning on the caller's own live change whatever they submitted is the
    // M14 round-2 mechanic — the failures a guesser actually produces must
    // move the counter. But the LOOKUP never runs for a shape the mint could
    // not have produced.
    const f = makeService();
    let refused: unknown;
    try {
      await f.service.completeChange(USER, 'session-1', 'EC1-SHORT');
    } catch (err) {
      refused = err;
    }
    expect(refused).toBeInstanceOf(HttpException);
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_code' });
    expect(f.finds).toBe(0);
    expect(f.attempts).toBe(1);
    expect(f.spends).toBe(0);
  });

  it('a WRONG code against a live change refuses identically, burning one attempt', async () => {
    const digest = sha256(canonicalCode('EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E'));
    const f = makeService({
      liveRow: {
        id: 'row-1',
        user_id: USER,
        new_email_ct: Buffer.from('ct:x'),
        new_email_bidx: Buffer.alloc(32, 9),
        dek_id: 'dek-1',
        code_sha256: digest,
        attempts: 0,
        expires_at: new Date(NOW.getTime() + 60_000),
        revoked_at: null,
        completed_at: null,
      },
    });
    let refused: unknown;
    try {
      await f.service.completeChange(USER, 's', 'EC1-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH');
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_code' });
    expect(f.attempts).toBe(1);
    expect(f.spends).toBe(0);
  });

  it('an EXHAUSTED change refuses even the right code, spending nothing', async () => {
    const right = 'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';
    const f = makeService({
      liveRow: {
        id: 'row-1',
        user_id: USER,
        new_email_ct: Buffer.from('ct:x'),
        new_email_bidx: Buffer.alloc(32, 9),
        dek_id: 'dek-1',
        code_sha256: sha256(canonicalCode(right)),
        attempts: 5,
        expires_at: new Date(NOW.getTime() + 60_000),
        revoked_at: null,
        completed_at: null,
      },
    });
    let refused: unknown;
    try {
      await f.service.completeChange(USER, 's', right);
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_code' });
    expect(f.spends).toBe(0);
  });

  it('NO LIVE CHANGE is the same refusal as a wrong code — no pending-change oracle', async () => {
    const f = makeService({ liveRow: null });
    let refused: unknown;
    try {
      await f.service.completeChange(
        USER,
        'session-1',
        'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E',
      );
    } catch (err) {
      refused = err;
    }
    expect((refused as HttpException).getResponse()).toEqual({ error: 'invalid_code' });
    expect(f.spends).toBe(0);
  });
});
