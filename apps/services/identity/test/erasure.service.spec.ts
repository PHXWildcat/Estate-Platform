/**
 * THE ERASURE DECISIONS AND THE DESTROY LEG, WITHOUT A DATABASE (M25 PR2/PR3).
 *
 * The companion to `erasure.int.spec.ts`, and the split between them is the
 * repo's rule rather than convenience. What lives in SQL — the status allowlist
 * riding inside the INSERT, the partial unique index, the grace-period
 * predicate, the capture trigger — can only be proved by a test that RUNS SQL,
 * and is proved there. What lives in TypeScript is the decision made from what
 * SQL returned, and the ORDER the steps are taken in. A fake can get those
 * wrong, so a fake can prove them right.
 *
 * ORDER IS WHY MOST OF PR3'S TESTS ARE HERE RATHER THAN IN THE INT SUITE. The
 * security property of the destroy leg is not any single write — it is that
 * closing the account and revoking its sessions both HAPPEN BEFORE the key is
 * destroyed, because `getOrCreateDek` mints a fresh DEK for a user who has no
 * active one and a surviving session would therefore un-erase the account and
 * leave the audit trail claiming success. A database cannot observe sequence
 * after the fact; a call log can.
 *
 * IT ALSO HAS TO RUN WITHOUT POSTGRES, and that is not incidental. CI measures
 * identity's coverage on a run with NO database (`IDENTITY_NO_DB_RUN`), because
 * that is the run its floor is calibrated for — so service logic reachable only
 * through a `describeIfPg` suite is, to that gate, untested code. PR2 shipped
 * with exactly that gap and CI caught it.
 */
import { ConflictException } from '@nestjs/common';
import { ERASURE_DOMAINS, type ErasureDomain } from '@estate/contracts';
import { emailBlindIndex, type FieldCrypto } from '@estate/crypto';
import type { IdentityConfig } from '../src/config';
import type { Db, Queryable } from '../src/db';
import type { PgDekRepository } from '../src/dek.repository';
import { ErasureService } from '../src/erasure.service';
import type { ErasureRepo, ErasureRequestRow } from '../src/erasure.repo';
import type { EventsService } from '../src/events.service';
import type { SessionsRepo } from '../src/sessions.repo';
import type { UsersRepo, UserRow } from '../src/users.repo';

const NOW = new Date('2026-08-21T12:00:00.000Z');
const GRACE_MS = 7 * 24 * 60 * 60 * 1000;
const USER = '11111111-1111-4111-8111-111111111111';
const SESSION = '22222222-2222-4222-8222-222222222222';
const REQUEST = '33333333-3333-4333-8333-333333333333';
const DEK = '44444444-4444-4444-8444-444444444444';
const INDEX_KEY = Buffer.alloc(32, 9);

function row(over: Partial<ErasureRequestRow> = {}): ErasureRequestRow {
  return {
    id: REQUEST,
    user_id: USER,
    status: 'pending',
    requested_at: NOW,
    cancelled_at: null,
    ...over,
  };
}

function user(over: Partial<UserRow> = {}): UserRow {
  return {
    id: USER,
    password_hash: 'x',
    status: 'active',
    dek_id: DEK,
    email_bidx: emailBlindIndex(INDEX_KEY, 'owner@example.test'),
    ...over,
  };
}

interface Parts {
  repo?: Partial<ErasureRepo>;
  users?: Partial<UsersRepo>;
  sessions?: Partial<SessionsRepo>;
  crypto?: Partial<FieldCrypto>;
  deks?: Partial<PgDekRepository>;
}

interface Harness {
  service: ErasureService;
  audited: string[];
  /** Every fake interaction, in the order it happened. The subject of PR3. */
  log: string[];
  seeded: ErasureDomain[][];
  bidx: Buffer[];
  cutoffs: Date[];
}

/**
 * `withTransaction` runs the callback against a sentinel Queryable. The fakes
 * ignore it — what is under test is the decision tree and the sequence, and the
 * statements themselves are the int suite's subject.
 */
function harness(parts: Parts = {}): Harness {
  const audited: string[] = [];
  const log: string[] = [];
  const seeded: ErasureDomain[][] = [];
  const bidx: Buffer[] = [];
  const cutoffs: Date[] = [];

  const db = {
    withTransaction: <T>(_actor: string, fn: (tx: Queryable) => Promise<T>): Promise<T> =>
      fn({} as Queryable),
    query: (): Promise<never[]> => Promise.resolve([]),
  } as unknown as Db;

  function tracked<T extends object>(name: string, impl: T): T {
    return new Proxy(impl, {
      get(target, prop: string) {
        const value = (target as Record<string, unknown>)[prop];
        if (typeof value !== 'function') {
          return value;
        }
        return (...args: unknown[]): unknown => {
          log.push(`${name}.${prop}`);
          return (value as (...a: unknown[]) => unknown)(...args);
        };
      },
    });
  }

  const repo = tracked<ErasureRepo>('repo', {
    claimDue: (_tx: unknown, cutoff: Date) => {
      cutoffs.push(cutoff);
      return Promise.resolve(null);
    },
    seedDomains: (_tx: unknown, _id: string, domains: readonly ErasureDomain[]) => {
      seeded.push([...domains]);
      return Promise.resolve();
    },
    releaseClaim: () => Promise.resolve(),
    markDomainDone: () => Promise.resolve(),
    completeIfAllDone: () => Promise.resolve(false),
    findLive: () => Promise.resolve(null),
    cancel: () => Promise.resolve(null),
    statusOf: () => Promise.resolve(null),
    insertIfPermitted: () => Promise.resolve(null),
    ...parts.repo,
  });

  const users = tracked('users', {
    findById: () => Promise.resolve(user()),
    closeAndUnlinkEmail: (_tx: unknown, _id: string, _from: unknown, b: Buffer) => {
      bidx.push(b);
      return Promise.resolve({ id: USER, dek_id: DEK });
    },
    ...parts.users,
  } as unknown as UsersRepo);

  const sessions = tracked('sessions', {
    revokeAllForUser: () => Promise.resolve([SESSION]),
    ...parts.sessions,
  } as unknown as SessionsRepo);

  const crypto = tracked('crypto', {
    destroyDek: () => Promise.resolve(),
    ...parts.crypto,
  } as unknown as FieldCrypto);

  const deks = tracked('deks', {
    findById: () => Promise.resolve({ dekId: DEK, destroyedAt: null }),
    ...parts.deks,
  } as unknown as PgDekRepository);

  const events = {
    accountErasureRequested: (): Promise<void> => push('requested'),
    accountErasureCancelled: (): Promise<void> => push('cancelled'),
    userClosedForErasure: (): Promise<void> => push('status_changed'),
    sessionsRevokedForErasure: (): Promise<void> => push('sessions_revoked'),
    dekDestroyed: (): Promise<void> => push('dek_destroyed'),
  } as unknown as EventsService;

  function push(name: string): Promise<void> {
    audited.push(name);
    log.push(`audit.${name}`);
    return Promise.resolve();
  }

  const config = {
    erasureGracePeriodMs: GRACE_MS,
    emailIndexKey: INDEX_KEY,
  } as unknown as IdentityConfig;

  return {
    service: new ErasureService(db, repo, events, users, sessions, crypto, deks, config, () => NOW),
    audited,
    log,
    seeded,
    bidx,
    cutoffs,
  };
}

describe('erasure decisions (no database)', () => {
  it('returns the new request and audits it', async () => {
    const h = harness({ repo: { insertIfPermitted: () => Promise.resolve(row()) } });
    await expect(h.service.request(USER, SESSION)).resolves.toEqual({
      status: 'pending',
      requestedAt: NOW.toISOString(),
    });
    expect(h.audited).toEqual(['requested']);
  });

  it('a zero-row insert with a LIVE request is idempotent, not a refusal', async () => {
    // The count cannot say which happened, so the service re-reads. Getting
    // this branch backwards would answer a conflict to a user pressing a button
    // twice — and, worse, would make `statusOf` decide the answer for an
    // account that is perfectly entitled to erasure.
    const h = harness({
      repo: {
        insertIfPermitted: () => Promise.resolve(null),
        findLive: () => Promise.resolve(row()),
        statusOf: () => Promise.reject(new Error('must not be consulted')),
      },
    });
    await expect(h.service.request(USER, SESSION)).resolves.toEqual({
      status: 'pending',
      requestedAt: NOW.toISOString(),
    });
  });

  it('AUDITS THE SECOND PRESS TOO — the answer is idempotent, the record is not', async () => {
    // A deliberate decision rather than an oversight: the request row is
    // unchanged, but somebody asked again and the trail should say so. An
    // erasure is the one place where under-recording is the wrong direction.
    const h = harness({
      repo: {
        insertIfPermitted: () => Promise.resolve(null),
        findLive: () => Promise.resolve(row()),
      },
    });
    await h.service.request(USER, SESSION);
    expect(h.audited).toEqual(['requested']);
  });

  it('carries the live STATUS through, so executing never renders as pending', async () => {
    // PR2 could hard-code 'pending'; PR3 cannot. The difference is the one a
    // user most needs — 'pending' can still be withdrawn, 'executing' cannot.
    const h = harness({
      repo: {
        insertIfPermitted: () => Promise.resolve(null),
        findLive: () => Promise.resolve(row({ status: 'executing' })),
      },
    });
    await expect(h.service.request(USER, SESSION)).resolves.toMatchObject({
      status: 'executing',
    });
  });

  it('maps a reported-dead owner to its own token', async () => {
    const h = harness({
      repo: {
        insertIfPermitted: () => Promise.resolve(null),
        findLive: () => Promise.resolve(null),
        statusOf: () => Promise.resolve('deceased_pending'),
      },
    });
    await expect(h.service.request(USER, SESSION)).rejects.toThrow(ConflictException);
    await expect(h.service.request(USER, SESSION)).rejects.toMatchObject({
      response: { error: 'open_death_report' },
    });
    expect(h.audited).toEqual([]);
  });

  it('maps every other status — and a MISSING user — to the generic token', async () => {
    for (const status of ['locked', 'suspended', 'settlement', 'closed', null]) {
      const h = harness({
        repo: {
          insertIfPermitted: () => Promise.resolve(null),
          findLive: () => Promise.resolve(null),
          statusOf: () => Promise.resolve(status),
        },
      });
      await expect(h.service.request(USER, SESSION)).rejects.toMatchObject({
        response: { error: 'erasure_not_permitted' },
      });
    }
  });

  it('cancels and audits when there was something to cancel', async () => {
    const h = harness({
      repo: { cancel: () => Promise.resolve(row({ status: 'cancelled', cancelled_at: NOW })) },
    });
    await expect(h.service.cancel(USER, SESSION)).resolves.toBeNull();
    expect(h.audited).toEqual(['cancelled']);
  });

  it('does NOT audit a cancel that cancelled nothing', async () => {
    // Pressing a protective verb twice must be safe, and the trail must not
    // fill with events for things that did not happen — an audit stream that
    // records non-events is one an investigator learns to discount.
    const h = harness({ repo: { cancel: () => Promise.resolve(null) } });
    await expect(h.service.cancel(USER, SESSION)).resolves.toBeNull();
    expect(h.audited).toEqual([]);
  });

  it('a cancel that came too late REPORTS the executing request, not null', async () => {
    // Two outcomes, two answers. "Nothing to cancel" and "the driver already
    // has it" need different things from the reader, and telling an owner
    // "withdrawn" about an erasure that is destroying keys would be the worst
    // lie this product could tell.
    const h = harness({
      repo: {
        cancel: () => Promise.resolve(null),
        findLive: () => Promise.resolve(row({ status: 'executing' })),
      },
    });
    await expect(h.service.cancel(USER, SESSION)).resolves.toEqual({
      status: 'executing',
      requestedAt: NOW.toISOString(),
    });
    expect(h.audited).toEqual([]);
  });

  it('get() reads the live request and never mints one', async () => {
    const h = harness({ repo: { findLive: () => Promise.resolve(row()) } });
    await expect(h.service.get(USER)).resolves.toEqual({
      status: 'pending',
      requestedAt: NOW.toISOString(),
    });
    expect(h.log).not.toContain('repo.insertIfPermitted');
  });

  it('get() answers null rather than inventing a state', async () => {
    const h = harness({ repo: { findLive: () => Promise.resolve(null) } });
    await expect(h.service.get(USER)).resolves.toBeNull();
  });
});

describe('the destroy leg (no database)', () => {
  /** Claims exactly one request, then reports the queue empty. */
  function oneDue(over: Partial<ErasureRequestRow> = {}): Partial<ErasureRepo> {
    let served = false;
    return {
      claimDue: (_tx, cutoff) => {
        void cutoff;
        if (served) {
          return Promise.resolve(null);
        }
        served = true;
        return Promise.resolve(row({ status: 'executing', ...over }));
      },
    };
  }

  it('does nothing at all when nothing is due', async () => {
    const h = harness();
    await expect(h.service.runDueErasures(NOW)).resolves.toBe(0);
    expect(h.log).toEqual(['repo.claimDue']);
    expect(h.audited).toEqual([]);
  });

  it('the grace period is subtracted from now to make the cutoff', async () => {
    // The whole waiting period is this arithmetic plus one SQL predicate. A
    // cutoff of `now` would execute a request the instant it was made and make
    // PR2's ungated cancel a button that can never be pressed in time.
    const h = harness();
    await h.service.runDueErasures(NOW);
    expect(h.cutoffs).toEqual([new Date(NOW.getTime() - GRACE_MS)]);
  });

  it('seeds EVERY participant domain, inside the claim transaction', async () => {
    // Seeded with the claim on purpose: a crash between the two would leave a
    // request executing with an empty ledger, and `completeIfAllDone` reads an
    // empty ledger as "every domain is done".
    const h = harness({ repo: oneDue() });
    await h.service.runDueErasures(NOW);
    expect(h.seeded).toEqual([[...ERASURE_DOMAINS]]);
    expect(h.log.indexOf('repo.seedDomains')).toBe(h.log.indexOf('repo.claimDue') + 1);
  });

  it('CLOSES AND REVOKES BEFORE IT DESTROYS — the ordering that is the control', async () => {
    // Reversed, this silently un-erases the account: `getOrCreateDek` MINTS a
    // key for a user with no active one, so a session surviving the destroy
    // gives the row a brand-new DEK, makes everything written afterwards
    // readable, and leaves the trail saying the erasure succeeded.
    const h = harness({ repo: oneDue() });
    await expect(h.service.runDueErasures(NOW)).resolves.toBe(1);

    const closed = h.log.indexOf('users.closeAndUnlinkEmail');
    const revoked = h.log.indexOf('sessions.revokeAllForUser');
    const destroyed = h.log.indexOf('crypto.destroyDek');
    expect(closed).toBeGreaterThanOrEqual(0);
    expect(revoked).toBeGreaterThan(closed);
    expect(destroyed).toBeGreaterThan(revoked);
  });

  it('files the three events of the leg, and the shred is the last of them', async () => {
    const h = harness({ repo: oneDue() });
    await h.service.runDueErasures(NOW);
    expect(h.audited).toEqual(['status_changed', 'sessions_revoked', 'dek_destroyed']);
  });

  it('marks its own domain done and asks whether the request is finished', async () => {
    const h = harness({ repo: oneDue() });
    await h.service.runDueErasures(NOW);
    expect(h.log.indexOf('repo.markDomainDone')).toBeGreaterThan(
      h.log.indexOf('crypto.destroyDek'),
    );
    expect(h.log).toContain('repo.completeIfAllDone');
  });

  it('replaces the blind index with a real one of the same shape, fresh each time', async () => {
    // Not random bytes: built through `emailBlindIndex`, so the width, the HMAC
    // key and the purpose label cannot drift from the live ones. A replacement
    // of the wrong shape would make every erased row identifiable by its column
    // alone — a worse leak than the lookup it removes.
    const h = harness({
      repo: {
        claimDue: (() => {
          let n = 0;
          // DISTINCT IDS, because the driver refuses to work one request twice
          // in a sweep. A fake handing back the same row is not modelling a
          // queue, it is modelling the bug the backstop exists to stop.
          return () =>
            Promise.resolve(n < 2 ? row({ id: `req-${n++}`, status: 'executing' }) : null);
        })(),
      },
    });
    await expect(h.service.runDueErasures(NOW)).resolves.toBe(2);
    expect(h.bidx).toHaveLength(2);
    const live = emailBlindIndex(INDEX_KEY, 'owner@example.test');
    for (const value of h.bidx) {
      expect(value).toHaveLength(live.length);
      expect(value.equals(live)).toBe(false);
    }
    expect(h.bidx[0]?.equals(h.bidx[1] as Buffer)).toBe(false);
  });

  it('SKIPS a DEK already destroyed — a retry cannot re-shred or double-file', async () => {
    // The irreversible step is guarded by the fact, not by a flag. A resumed
    // run finds `destroyedAt` set, emits nothing, and leaves the original
    // timestamp — which is the one an investigator will rely on.
    const h = harness({
      repo: oneDue(),
      users: { findById: () => Promise.resolve(user({ status: 'closed' })) },
      deks: {
        findById: () => Promise.resolve({ dekId: DEK, destroyedAt: NOW } as never),
      },
    });
    await h.service.runDueErasures(NOW);
    expect(h.log).not.toContain('crypto.destroyDek');
    expect(h.audited).toEqual([]);
    // It still finishes the ledger — that is what makes the retry useful.
    expect(h.log).toContain('repo.markDomainDone');
  });

  it('RELEASES the claim, destroying nothing, when the account became ineligible', async () => {
    // A death report or a settlement lock landed in the grace period. Releasing
    // rather than failing keeps the owner in control: a request wedged in
    // 'executing' is uncancellable AND blocks a new one through the live index
    // — the erasure feature locked shut for that account, by a race.
    const h = harness({
      repo: oneDue(),
      users: { closeAndUnlinkEmail: () => Promise.resolve(null) },
    });
    await h.service.runDueErasures(NOW);
    expect(h.log).toContain('repo.releaseClaim');
    expect(h.log).not.toContain('crypto.destroyDek');
    expect(h.log).not.toContain('repo.markDomainDone');
    expect(h.audited).toEqual([]);
  });

  it('destroys nothing when the user row is gone, and does not report success', async () => {
    const h = harness({
      repo: oneDue(),
      users: { findById: () => Promise.resolve(null) },
    });
    await h.service.runDueErasures(NOW);
    expect(h.log).not.toContain('crypto.destroyDek');
    // Deliberately NOT marked done: a request that quietly completed against a
    // missing user is exactly the record that would be believed later.
    expect(h.log).not.toContain('repo.markDomainDone');
  });

  it('drains the queue rather than taking one request per tick', async () => {
    let n = 0;
    const h = harness({
      repo: {
        claimDue: () =>
          Promise.resolve(n < 3 ? row({ id: `req-${n++}`, status: 'executing' }) : null),
      },
    });
    await expect(h.service.runDueErasures(NOW)).resolves.toBe(3);
    expect(h.audited.filter((a) => a === 'dek_destroyed')).toHaveLength(3);
  });

  it('STOPS rather than spins when the claim predicate stops narrowing', async () => {
    // The named test for the backstop, and the reason it exists: the failure it
    // guards is a driver that never returns, which no assertion can catch —
    // a hung sweep looks like a slow one until a timeout, and a timeout names
    // nothing. PR4's first draft of the resume arm did exactly this, asking
    // "does this request have unfinished work" when seven domains are
    // permanently unfinished.
    //
    // A repo that keeps handing back the SAME request is that regression
    // exactly. One pass, then stop — and the request it did carry is finished
    // and durable, so stopping costs nothing.
    const h = harness({
      repo: { claimDue: () => Promise.resolve(row({ status: 'executing' })) },
    });
    await expect(h.service.runDueErasures(NOW)).resolves.toBe(1);
    expect(h.audited.filter((a) => a === 'dek_destroyed')).toHaveLength(1);
  });
});
