/**
 * THE PASSKEY MANAGEMENT DECISION LAYER, with the repo faked (M17 PR5).
 *
 * `webauthn-management.int.spec.ts` proves the SQL — the owner predicate, the
 * revoked_at filters, the typed duplicate. This proves the choices above it:
 * what the projection maps, which ids are refused before any query, and which
 * outcomes emit the factor-weakening audit event.
 */
import { WebAuthnService } from '../src/webauthn.service';
import type { AuthEventsRepo } from '../src/auth-events.repo';
import type { IdentityConfig } from '../src/config';
import type { EventsService } from '../src/events.service';
import type { SecondFactorGate } from '../src/second-factor-gate';
import type { SessionsRepo } from '../src/sessions.repo';
import type { WebAuthnRepo } from '../src/webauthn.repo';

const USER = 'b6c9a1de-0000-4000-8000-000000000042';
const CRED = 'c1d2e3f4-0000-4000-8000-000000000001';
const NOW = new Date('2026-08-13T12:00:00.000Z');

function makeService(opts?: { revokeAnswers?: boolean }): {
  service: WebAuthnService;
  revokes: Array<{ userId: string; id: string }>;
  renames: Array<{ id: string; nickname: string }>;
  ledger: string[];
  audited: number;
} {
  const state = {
    revokes: [] as Array<{ userId: string; id: string }>,
    renames: [] as Array<{ id: string; nickname: string }>,
    ledger: [] as string[],
    audited: 0,
  };
  const service = new WebAuthnService(
    {
      listForUser: (): Promise<unknown[]> =>
        Promise.resolve([
          {
            id: CRED,
            nickname: 'MacBook',
            is_hardware_key: false,
            created_at: NOW,
            last_used_at: null,
          },
        ]),
      revokeCredential: (userId: string, id: string): Promise<boolean> => {
        state.revokes.push({ userId, id });
        return Promise.resolve(opts?.revokeAnswers ?? true);
      },
      renameCredential: (_u: string, id: string, nickname: string): Promise<boolean> => {
        state.renames.push({ id, nickname });
        return Promise.resolve(true);
      },
    } as unknown as WebAuthnRepo,
    {} as unknown as SessionsRepo,
    {
      insert: (input: { kind: string }): Promise<void> => {
        state.ledger.push(input.kind);
        return Promise.resolve();
      },
    } as unknown as AuthEventsRepo,
    {
      webauthnRevoked: (): Promise<void> => {
        state.audited += 1;
        return Promise.resolve();
      },
    } as unknown as EventsService,
    { rpId: 'localhost', rpOrigin: 'http://localhost:3000', rpName: 'Estate' } as IdentityConfig,
    () => NOW,
    {} as unknown as SecondFactorGate,
  );
  return {
    service,
    get revokes() {
      return state.revokes;
    },
    get renames() {
      return state.renames;
    },
    get ledger() {
      return state.ledger;
    },
    get audited() {
      return state.audited;
    },
  };
}

describe('the management projection', () => {
  it('maps rows to the wire shape — labels and timestamps, ISO strings, nothing else', async () => {
    const f = makeService();
    await expect(f.service.listCredentials(USER)).resolves.toEqual([
      {
        id: CRED,
        nickname: 'MacBook',
        isHardwareKey: false,
        createdAt: NOW.toISOString(),
        lastUsedAt: null,
      },
    ]);
  });
});

describe('revoke — the factor-weakening verb', () => {
  it('a MALFORMED id is refused before any query — uniform with not-found', async () => {
    const f = makeService();
    await expect(f.service.revokeCredential(USER, 'not-a-uuid')).resolves.toBe(false);
    expect(f.revokes).toEqual([]);
  });

  it('a real revoke writes the ledger kind AND the audit event', async () => {
    const f = makeService();
    await expect(f.service.revokeCredential(USER, CRED)).resolves.toBe(true);
    expect(f.revokes).toEqual([{ userId: USER, id: CRED }]);
    expect(f.ledger).toEqual(['webauthn.revoked']);
    expect(f.audited).toBe(1);
  });

  it('a refused revoke (unknown or not-yours) emits NOTHING — no event about a non-action', async () => {
    const f = makeService({ revokeAnswers: false });
    await expect(f.service.revokeCredential(USER, CRED)).resolves.toBe(false);
    expect(f.ledger).toEqual([]);
    expect(f.audited).toBe(0);
  });
});

describe('rename — the label verb', () => {
  it('guards the id shape, then delegates; no audit (a label is not a factor)', async () => {
    const f = makeService();
    await expect(f.service.renameCredential(USER, 'nope', 'x')).resolves.toBe(false);
    await expect(f.service.renameCredential(USER, CRED, 'YubiKey')).resolves.toBe(true);
    expect(f.renames).toEqual([{ id: CRED, nickname: 'YubiKey' }]);
    expect(f.audited).toBe(0);
  });
});
