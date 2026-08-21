/**
 * THE ERASURE DECISIONS, WITHOUT A DATABASE (M25 PR2).
 *
 * The companion to `erasure.int.spec.ts`, and the split between them is the
 * repo's rule rather than convenience. What lives in SQL — the status allowlist
 * riding inside the INSERT, the partial unique index, the capture trigger — can
 * only be proved by a test that RUNS SQL, and is proved there. What lives in
 * TypeScript is the decision made from what SQL returned: which refusal token a
 * status maps to, whether a zero-row insert means refused or already-requested,
 * and whether an audit event is emitted. A fake repo can get those wrong, so a
 * fake repo can prove them right.
 *
 * IT ALSO HAS TO RUN WITHOUT POSTGRES, and that is not incidental. CI measures
 * identity's coverage on a run with NO database (`IDENTITY_NO_DB_RUN`), because
 * that is the run its floor is calibrated for — so service logic reachable only
 * through a `describeIfPg` suite is, to that gate, untested code. PR2 shipped
 * with exactly that gap and CI caught it.
 */
import { ConflictException } from '@nestjs/common';
import type { Db, Queryable } from '../src/db';
import { ErasureService } from '../src/erasure.service';
import type { ErasureRepo, ErasureRequestRow } from '../src/erasure.repo';
import type { EventsService } from '../src/events.service';

const NOW = new Date('2026-08-21T12:00:00.000Z');
const USER = '11111111-1111-4111-8111-111111111111';
const SESSION = '22222222-2222-4222-8222-222222222222';
const REQUEST = '33333333-3333-4333-8333-333333333333';

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

interface Harness {
  service: ErasureService;
  audited: string[];
  calls: string[];
}

/**
 * `withTransaction` runs the callback against a sentinel Queryable. The fake
 * repo ignores it — what is under test here is the decision tree, and the
 * statements it would run are the int suite's subject.
 */
function harness(repo: Partial<ErasureRepo>): Harness {
  const audited: string[] = [];
  const calls: string[] = [];
  const db = {
    withTransaction: <T>(_actor: string, fn: (tx: Queryable) => Promise<T>): Promise<T> =>
      fn({} as Queryable),
    query: (): Promise<never[]> => Promise.resolve([]),
  } as unknown as Db;

  const tracked = new Proxy(repo, {
    get(target, prop: string) {
      calls.push(prop);
      return (target as Record<string, unknown>)[prop];
    },
  }) as ErasureRepo;

  const events = {
    accountErasureRequested: (): Promise<void> => {
      audited.push('requested');
      return Promise.resolve();
    },
    accountErasureCancelled: (): Promise<void> => {
      audited.push('cancelled');
      return Promise.resolve();
    },
  } as unknown as EventsService;

  return { service: new ErasureService(db, tracked, events, () => NOW), audited, calls };
}

describe('erasure decisions (no database)', () => {
  it('returns the new request and audits it', async () => {
    const h = harness({
      insertIfPermitted: () => Promise.resolve(row()),
    });
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
      insertIfPermitted: () => Promise.resolve(null),
      findLive: () => Promise.resolve(row()),
      statusOf: () => Promise.reject(new Error('must not be consulted')),
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
      insertIfPermitted: () => Promise.resolve(null),
      findLive: () => Promise.resolve(row()),
    });
    await h.service.request(USER, SESSION);
    expect(h.audited).toEqual(['requested']);
  });

  it('maps a reported-dead owner to its own token', async () => {
    const h = harness({
      insertIfPermitted: () => Promise.resolve(null),
      findLive: () => Promise.resolve(null),
      statusOf: () => Promise.resolve('deceased_pending'),
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
        insertIfPermitted: () => Promise.resolve(null),
        findLive: () => Promise.resolve(null),
        statusOf: () => Promise.resolve(status),
      });
      await expect(h.service.request(USER, SESSION)).rejects.toMatchObject({
        response: { error: 'erasure_not_permitted' },
      });
    }
  });

  it('cancels and audits when there was something to cancel', async () => {
    const h = harness({
      cancel: () => Promise.resolve(row({ status: 'cancelled', cancelled_at: NOW })),
    });
    await expect(h.service.cancel(USER, SESSION)).resolves.toBeNull();
    expect(h.audited).toEqual(['cancelled']);
  });

  it('does NOT audit a cancel that cancelled nothing', async () => {
    // Pressing a protective verb twice must be safe, and the trail must not
    // fill with events for things that did not happen — an audit stream that
    // records non-events is one an investigator learns to discount.
    const h = harness({ cancel: () => Promise.resolve(null) });
    await expect(h.service.cancel(USER, SESSION)).resolves.toBeNull();
    expect(h.audited).toEqual([]);
  });

  it('get() reads the live request and never mints one', async () => {
    const h = harness({ findLive: () => Promise.resolve(row()) });
    await expect(h.service.get(USER)).resolves.toEqual({
      status: 'pending',
      requestedAt: NOW.toISOString(),
    });
    expect(h.calls).not.toContain('insertIfPermitted');
  });

  it('get() answers null rather than inventing a state', async () => {
    const h = harness({ findLive: () => Promise.resolve(null) });
    await expect(h.service.get(USER)).resolves.toBeNull();
  });
});
