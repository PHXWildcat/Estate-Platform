import { randomUUID } from 'node:crypto';
import { ConflictException, NotFoundException } from '@nestjs/common';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import type { EventsService } from '../src/events.service';
import type { SessionsRepo } from '../src/sessions.repo';
import { SettlementLockService } from '../src/settlement-lock.service';
import type { UsersRepo } from '../src/users.repo';

const NOW = new Date('2026-07-27T12:00:00Z');
const USER = randomUUID();
const CASE = randomUUID();

function makeFakes(status: string | null): {
  users: { findById: jest.Mock; updateStatusFrom: jest.Mock };
  sessions: { revokeAllForUser: jest.Mock };
  authEvents: { insert: jest.Mock; lastOccurredAt: jest.Mock };
  events: { userStatusChanged: jest.Mock; sessionsRevokedAll: jest.Mock };
} {
  return {
    users: {
      findById: jest
        .fn()
        .mockResolvedValue(
          status === null ? null : { id: USER, password_hash: 'h', status, dek_id: randomUUID() },
        ),
      updateStatusFrom: jest.fn().mockResolvedValue(true),
    },
    sessions: { revokeAllForUser: jest.fn().mockResolvedValue(['s-1', 's-2']) },
    authEvents: { insert: jest.fn(), lastOccurredAt: jest.fn().mockResolvedValue(null) },
    events: { userStatusChanged: jest.fn(), sessionsRevokedAll: jest.fn() },
  };
}

function makeService(fakes: ReturnType<typeof makeFakes>): SettlementLockService {
  return new SettlementLockService(
    fakes.users as unknown as UsersRepo,
    fakes.sessions as unknown as SessionsRepo,
    fakes.authEvents as unknown as AuthEventsRepo,
    fakes.events as unknown as EventsService,
  );
}

describe('SettlementLockService.setState (identity-enforced transition table)', () => {
  it('locks an active account to deceased_pending and audits with the case id', async () => {
    const fakes = makeFakes('active');
    const result = await makeService(fakes).setState(USER, 'deceased_pending', CASE, NOW);
    expect(result).toEqual({ status: 'deceased_pending' });
    // No watermark on the pending lock: the liveness interlock guards only the
    // terminal 'settlement' transition.
    expect(fakes.users.updateStatusFrom).toHaveBeenCalledWith(
      USER,
      ['active'],
      'deceased_pending',
      undefined,
    );
    expect(fakes.events.userStatusChanged).toHaveBeenCalledWith(
      USER,
      'active',
      'deceased_pending',
      CASE,
    );
    // No bulk revocation at pending: the owner's live sessions are the rescue path.
    expect(fakes.sessions.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('verification (settlement) revokes every session and audits both effects', async () => {
    const fakes = makeFakes('deceased_pending');
    await makeService(fakes).setState(USER, 'settlement', CASE, NOW);
    expect(fakes.sessions.revokeAllForUser).toHaveBeenCalledWith(USER, 'settlement_verified', NOW);
    expect(fakes.events.sessionsRevokedAll).toHaveBeenCalledWith(USER, 2, CASE);
    expect(fakes.events.userStatusChanged).toHaveBeenCalledWith(
      USER,
      'deceased_pending',
      'settlement',
      CASE,
    );
  });

  it('restore (active) only ever comes from deceased_pending', async () => {
    const fakes = makeFakes('deceased_pending');
    await makeService(fakes).setState(USER, 'active', CASE, NOW);
    expect(fakes.users.updateStatusFrom).toHaveBeenCalledWith(
      USER,
      ['deceased_pending'],
      'active',
      undefined,
    );
  });

  it('is idempotent: setting the current state is a no-op with no audit', async () => {
    const fakes = makeFakes('deceased_pending');
    const result = await makeService(fakes).setState(USER, 'deceased_pending', CASE, NOW);
    expect(result).toEqual({ status: 'deceased_pending' });
    expect(fakes.users.updateStatusFrom).not.toHaveBeenCalled();
    expect(fakes.events.userStatusChanged).not.toHaveBeenCalled();
  });

  it.each([
    ['locking a suspended account', 'suspended', 'deceased_pending'],
    ['verifying an account that was never pending', 'active', 'settlement'],
    ['restoring a verified (settlement) account', 'settlement', 'active'],
  ] as const)('refuses %s with invalid_transition', async (_label, current, target) => {
    const fakes = makeFakes(current);
    // The CAS update matches nothing because the current status is outside the
    // allowed 'from' set for the target.
    fakes.users.updateStatusFrom.mockResolvedValue(false);
    await expect(makeService(fakes).setState(USER, target, CASE, NOW)).rejects.toThrow(
      ConflictException,
    );
    expect(fakes.events.userStatusChanged).not.toHaveBeenCalled();
    expect(fakes.sessions.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('404s an unknown user', async () => {
    const fakes = makeFakes(null);
    await expect(makeService(fakes).setState(USER, 'deceased_pending', CASE, NOW)).rejects.toThrow(
      NotFoundException,
    );
  });

  it('forwards the liveness watermark into the compare-and-set statement', async () => {
    const fakes = makeFakes('deceased_pending');
    const watermark = new Date('2026-07-20T00:00:00Z');
    await makeService(fakes).setState(USER, 'settlement', CASE, NOW, watermark);
    expect(fakes.users.updateStatusFrom).toHaveBeenCalledWith(
      USER,
      ['deceased_pending'],
      'settlement',
      watermark,
    );
  });

  it('reports owner_alive (not invalid_transition) when the interlock fires', async () => {
    const fakes = makeFakes('deceased_pending');
    const watermark = new Date('2026-07-20T00:00:00Z');
    // The atomic UPDATE matched nothing, and the ledger shows a step-up after
    // the watermark: the owner is alive, and the caller must void — not retry.
    fakes.users.updateStatusFrom.mockResolvedValue(false);
    fakes.authEvents.lastOccurredAt.mockResolvedValue(new Date('2026-07-25T00:00:00Z'));
    await expect(
      makeService(fakes).setState(USER, 'settlement', CASE, NOW, watermark),
    ).rejects.toMatchObject({ response: { error: 'owner_alive' } });
    expect(fakes.sessions.revokeAllForUser).not.toHaveBeenCalled();
  });

  it('still reports invalid_transition when the CAS failed for any other reason', async () => {
    const fakes = makeFakes('deceased_pending');
    fakes.users.updateStatusFrom.mockResolvedValue(false);
    fakes.authEvents.lastOccurredAt.mockResolvedValue(new Date('2026-07-01T00:00:00Z'));
    await expect(
      makeService(fakes).setState(USER, 'settlement', CASE, NOW, new Date('2026-07-20T00:00:00Z')),
    ).rejects.toMatchObject({ response: { error: 'invalid_transition' } });
  });
});

describe('SettlementLockService.liveness', () => {
  it('returns the status and the last step-up grant from the append-only ledger', async () => {
    const fakes = makeFakes('deceased_pending');
    const stepUpAt = new Date('2026-07-26T09:00:00Z');
    fakes.authEvents.lastOccurredAt.mockResolvedValue(stepUpAt);
    const result = await makeService(fakes).liveness(USER);
    expect(result).toEqual({ status: 'deceased_pending', lastStepUpAt: stepUpAt });
    expect(fakes.authEvents.lastOccurredAt).toHaveBeenCalledWith(USER, 'stepup.granted');
  });

  it('returns null when the user has never stepped up', async () => {
    const fakes = makeFakes('active');
    const result = await makeService(fakes).liveness(USER);
    expect(result.lastStepUpAt).toBeNull();
  });

  it('404s an unknown user', async () => {
    const fakes = makeFakes(null);
    await expect(makeService(fakes).liveness(USER)).rejects.toThrow(NotFoundException);
  });
});
