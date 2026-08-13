/**
 * THE RESET-REQUEST BOUND, and the uniformity it must not break (M17 PR3).
 *
 * `password-reset.int.spec.ts` proves the SQL. This proves the decisions that
 * sit in front of it — which are the ones that make an unauthenticated
 * mail-sending route safe to expose at all:
 *
 *  · the per-address bound refuses BEFORE any lookup, so an abuser cannot drive
 *    unlimited mail at a stranger's inbox;
 *  · the refusal is SILENT, so the route still tells a caller nothing;
 *  · nothing observable differs between an address with an account and one
 *    without — which is the property the whole request path is arranged around.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HttpException } from '@nestjs/common';
import { PasswordResetService, RESET_FLOOR_MS } from '../src/password-reset.service';
import { RESET_ADDRESS_BOUND } from '../src/rate-bounds';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import type { Db } from '../src/db';
import type { EventsService } from '../src/events.service';
import type { PasswordHasher } from '../src/password';
import type { PasswordResetRepo } from '../src/password-reset.repo';
import type { SessionsRepo } from '../src/sessions.repo';
import type { UsersRepo } from '../src/users.repo';

const NOW = new Date('2026-08-13T12:00:00.000Z');

interface Fakes {
  lookups: number;
  mailed: string[];
  throttled: number;
  minted: number;
  service: PasswordResetService;
}

/** A repo double whose `findByCode` answer each case chooses. */
function makeRedeemService(row: unknown): {
  service: PasswordResetService;
  spends: number;
  hashes: number;
} {
  const state = { spends: 0, hashes: 0 };
  const service = new PasswordResetService(
    {} as unknown as UsersRepo,
    {} as unknown as SessionsRepo,
    {
      findByCode: (): Promise<unknown> => Promise.resolve(row),
      markRedeemed: (): Promise<boolean> => {
        state.spends += 1;
        return Promise.resolve(true);
      },
    } as unknown as PasswordResetRepo,
    { insert: (): Promise<void> => Promise.resolve() } as unknown as AuthEventsRepo,
    {
      hashPassword: (): Promise<string> => {
        state.hashes += 1;
        return Promise.resolve('argon2');
      },
    } as unknown as PasswordHasher,
    { passwordResetFailed: (): Promise<void> => Promise.resolve() } as unknown as EventsService,
    {} as unknown as Db,
    { emailIndexKey: Buffer.alloc(32, 3) } as unknown as IdentityConfig,
    () => NOW,
    {} as never,
  );
  return {
    service,
    get spends(): number {
      return state.spends;
    },
    get hashes(): number {
      return state.hashes;
    },
  };
}

function makeService(opts: { userExists: boolean }): Fakes {
  const state = { lookups: 0, mailed: [] as string[], throttled: 0, minted: 0 };
  const service = new PasswordResetService(
    {
      findByEmailBidx: (): Promise<unknown> => {
        state.lookups += 1;
        return Promise.resolve(
          opts.userExists ? { id: 'u-1', status: 'active', password_hash: 'h', dek_id: 'd' } : null,
        );
      },
    } as unknown as UsersRepo,
    {} as unknown as SessionsRepo,
    {
      lastMintedAt: (): Promise<Date | null> => Promise.resolve(null),
      revokeLive: (): Promise<boolean> => Promise.resolve(false),
      insert: (): Promise<string> => {
        state.minted += 1;
        return Promise.resolve('row-1');
      },
    } as unknown as PasswordResetRepo,
    { insert: (): Promise<void> => Promise.resolve() } as unknown as AuthEventsRepo,
    {} as unknown as PasswordHasher,
    {
      passwordResetRequested: (): Promise<void> => Promise.resolve(),
      passwordResetThrottled: (): Promise<void> => {
        state.throttled += 1;
        return Promise.resolve();
      },
    } as unknown as EventsService,
    {} as unknown as Db,
    { emailIndexKey: Buffer.alloc(32, 3) } as unknown as IdentityConfig,
    () => NOW,
    {
      sendPasswordReset: (input: { code: string }): Promise<{ accepted: boolean }> => {
        state.mailed.push(input.code);
        return Promise.resolve({ accepted: true });
      },
    } as never,
  );
  return {
    service,
    get lookups() {
      return state.lookups;
    },
    get mailed() {
      return state.mailed;
    },
    get throttled() {
      return state.throttled;
    },
    get minted() {
      return state.minted;
    },
  };
}

describe('the reset-request bound', () => {
  it('REFUSES past the cap, and does so BEFORE any lookup', async () => {
    const f = makeService({ userExists: true });
    for (let i = 0; i < RESET_ADDRESS_BOUND.max; i += 1) {
      await f.service.requestReset('victim@example.com');
    }
    const lookupsBefore = f.lookups;

    await f.service.requestReset('victim@example.com');

    // No further work of any kind: the bound short-circuits ahead of the
    // database, so an abuser cannot even make the platform look somebody up.
    expect(f.lookups).toBe(lookupsBefore);
    expect(f.mailed).toHaveLength(RESET_ADDRESS_BOUND.max);
    expect(f.throttled).toBe(1);
  });

  it('the refusal is SILENT — the method resolves to nothing either way', async () => {
    // The bound's whole point is that a dropped request is indistinguishable
    // from a delivered one. `requestReset` resolves to void whether it mailed,
    // refused, or found nobody — there is no channel for it to differ on — and
    // the route-level half (the controller does not await it at all) is pinned
    // by the source assertion below; asserted so a future edit that starts
    // returning an outcome has to come here and think about it.
    const f = makeService({ userExists: true });
    await expect(f.service.requestReset('a@example.com')).resolves.toBeUndefined();
  });

  it('bounds each address SEPARATELY', async () => {
    const f = makeService({ userExists: true });
    for (let i = 0; i < RESET_ADDRESS_BOUND.max; i += 1) {
      await f.service.requestReset('victim@example.com');
    }
    await f.service.requestReset('someone-else@example.com');
    expect(f.mailed).toHaveLength(RESET_ADDRESS_BOUND.max + 1);
  });
});

describe('the request path tells a caller nothing', () => {
  it('an address WITH an account and one WITHOUT are indistinguishable to the caller', async () => {
    // Same resolved value either way. The timing half — an existing account
    // must not ANSWER measurably later — is the ROUTE's property now: the
    // controller calls this without awaiting it, which the source pin below
    // holds. Register's own docstring records that timing residual as still
    // open; this route avoids inheriting it at the controller line.
    const withAccount = makeService({ userExists: true });
    const without = makeService({ userExists: false });

    await expect(withAccount.service.requestReset('real@example.com')).resolves.toBeUndefined();
    await expect(without.service.requestReset('nobody@example.com')).resolves.toBeUndefined();

    // …and only the real one caused a mint, which the caller cannot observe.
    expect(withAccount.minted).toBe(1);
    expect(without.minted).toBe(0);
    expect(without.mailed).toEqual([]);
  });

  it('THE ROUTE DOES NOT AWAIT THE WORK — pinned at the source, where it lives', () => {
    // `requestReset` is awaitable so every TEST in this repo can drive the
    // chain deterministically (the M14 `ensureVerificationRequested` shape —
    // the first version detached inside the service and forced the int spec
    // into a bare 25ms sleep that flaked in CI). The cost of awaitability is
    // that the controller COULD await it, and an awaited mint would make an
    // existing account answer measurably later than a stranger's address — the
    // account-existence oracle this route is arranged around. A runtime test
    // cannot tell a fast await from no await (the M17 PR1 ordering-pin rule),
    // so the property is asserted against the handler's source.
    const controller = readFileSync(
      join(__dirname, '..', 'src', 'auth.controller.ts'),
      'utf8',
    ).replace(/\/\*[\s\S]*?\*\//g, '');

    // The handler exists and is SYNCHRONOUS — a sync method structurally
    // cannot await anything, which is the strongest form of the pin.
    expect(controller).toMatch(
      /requestPasswordReset\(@Body\(\) body: unknown\): \{ status: string \}/,
    );
    // The call is explicitly detached, with a terminal catch.
    expect(controller).toMatch(/void this\.passwordReset\.requestReset\(email\)\.catch/);
    expect(controller).not.toMatch(/await this\.passwordReset\.requestReset/);
  });

  it('the floor is a real number, and wider than the authenticated ceremony’s', () => {
    // Not arithmetic for its own sake: M14's five-minute floor guards a route
    // that mails the CALLER their own address, while this one is reachable by
    // anyone who can type an address they do not own.
    expect(RESET_FLOOR_MS).toBeGreaterThan(5 * 60 * 1000);
    expect(RESET_ADDRESS_BOUND.max).toBeLessThan(20);
  });
});

/**
 * THE REDEMPTION DECISIONS, with the repo faked.
 *
 * `password-reset.int.spec.ts` proves the SQL. These are the branches ABOVE it
 * — which code shapes are refused before a lookup, and which repo answers are
 * treated as dead — and they are the layer that decides whether the uniform
 * refusal is actually uniform.
 */
describe('completeReset refuses every dead code the same way', () => {
  const live = {
    id: 'row-1',
    user_id: 'u-1',
    expires_at: new Date(NOW.getTime() + 60_000),
    revoked_at: null,
    redeemed_at: null,
  };
  const MINTED = 'PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';

  it('a MIS-SHAPED code is refused before any lookup, and costs no hash', async () => {
    // Measured on the CANONICAL form against a length derived from the mint —
    // the M13 round-3 finding, where a raw min(8) was satisfied by separators
    // alone and folded to the empty string.
    const f = makeRedeemService(live);
    await expect(
      f.service.completeReset('PR1-TOO-SHORT', 'a-new-password-x'),
    ).rejects.toMatchObject({ response: { error: 'invalid_code' } });
    expect(f.spends).toBe(0);
    expect(f.hashes).toBe(0);
  });

  it.each([
    ['unknown', null],
    ['revoked', { ...live, revoked_at: new Date(NOW.getTime() - 1000) }],
    ['already spent', { ...live, redeemed_at: new Date(NOW.getTime() - 1000) }],
    ['expired', { ...live, expires_at: new Date(NOW.getTime() - 1000) }],
  ])('a %s code is refused IDENTICALLY, and nothing is spent', async (_name, row) => {
    // One token for every dead reason. Distinguishing them would tell whoever
    // holds a guess that it named something real, and on an unauthenticated
    // route it would leak account state as well.
    const f = makeRedeemService(row);
    let refused: unknown;
    try {
      await f.service.completeReset(MINTED, 'a-new-password-x');
    } catch (err) {
      refused = err;
    }
    // Typed rather than cast: these cases assert an exact status and body, and
    // an `any` would let a typo in a property name assert nothing.
    expect(refused).toBeInstanceOf(HttpException);
    const thrown = refused as HttpException;
    expect(thrown.getStatus()).toBe(400);
    expect(thrown.getResponse()).toEqual({ error: 'invalid_code' });
    expect(f.spends).toBe(0);
    // The new password is never hashed for a code that cannot be spent.
    expect(f.hashes).toBe(0);
  });
});
