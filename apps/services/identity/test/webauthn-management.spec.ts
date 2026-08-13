/**
 * THE PASSKEY MANAGEMENT DECISION LAYER, with the repo faked (M17 PR5).
 *
 * `webauthn-management.int.spec.ts` proves the SQL — the owner predicate, the
 * revoked_at filters, the typed duplicate. This proves the choices above it:
 * what the projection maps, which ids are refused before any query, and which
 * outcomes emit the factor-weakening audit event.
 */
import { HttpException } from '@nestjs/common';
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

function makeService(opts?: {
  revokeAnswers?: boolean;
  challenge?: string | null;
  credential?: unknown;
}): {
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
      consumeChallenge: (): Promise<string | null> =>
        Promise.resolve(opts?.challenge === undefined ? 'a-live-challenge' : opts.challenge),
      findCredentialById: (): Promise<unknown> => Promise.resolve(opts?.credential ?? null),
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
    // The clone branch's notifier. REFUSING by default, not succeeding: these
    // cases never reach it, and a double that quietly succeeded would make an
    // unreachable path look healthy (the M17 PR2 faithful-refusal rule).
    {
      sendAccountSecurity: (): Promise<{ accepted: boolean }> =>
        Promise.resolve({ accepted: false }),
    } as never,
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

/**
 * EVERY FAILING ASSERTION BRANCH IS ON THE LEDGER (the M17 PR6 review).
 *
 * PR5 added `webauthn.assertion_failed` to correct a 2026-08-10 decision-log
 * entry that claimed failed assertions "emit their own kind" while the code
 * emitted nothing. The review found the correction INCOMPLETE: only the
 * crypto-verify catch and the userVerified recheck recorded, so the two
 * branches that short-circuit EARLIEST — no live challenge, and a credential id
 * that names nothing or names somebody else's authenticator — stayed silent.
 *
 * MEASURED on the running stack before this was written: ten probes against a
 * live account (five with no challenge, five submitting a foreign credential id
 * after minting a real challenge) produced ZERO `webauthn.*` rows. The foreign
 * credential id is the most suspicious probe class there is — no browser
 * produces one by accident — and it was the one that left no trace.
 */
describe('every failing assertion branch reaches the ledger', () => {
  const SESSION = 'd4e5f6a7-0000-4000-8000-000000000009';
  const RESPONSE = { id: 'Zm9yZWlnbi1jcmVk', rawId: 'Zm9yZWlnbi1jcmVk', type: 'public-key' };

  it('NO LIVE CHALLENGE records — a replayed assertion body looks exactly like this', async () => {
    const f = makeService({ challenge: null });
    await expect(
      f.service.finishAuthentication(USER, SESSION, RESPONSE as never),
    ).rejects.toMatchObject({ response: { error: 'webauthn_failed' } });
    expect(f.ledger).toEqual(['webauthn.assertion_failed']);
  });

  it('A FOREIGN OR UNKNOWN CREDENTIAL records — the probe class that was silent', async () => {
    // findCredentialById answers null (unknown id) …
    const unknown = makeService({ credential: null });
    await expect(
      unknown.service.finishAuthentication(USER, SESSION, RESPONSE as never),
    ).rejects.toMatchObject({ response: { error: 'webauthn_failed' } });
    expect(unknown.ledger).toEqual(['webauthn.assertion_failed']);

    // … and a credential that exists but belongs to SOMEBODY ELSE.
    const foreign = makeService({
      credential: {
        credential_id: Buffer.from('x'),
        public_key: Buffer.from('k'),
        sign_count: '0',
        transports: null,
        user_id: 'a-different-user',
      },
    });
    await expect(
      foreign.service.finishAuthentication(USER, SESSION, RESPONSE as never),
    ).rejects.toMatchObject({ response: { error: 'webauthn_failed' } });
    expect(foreign.ledger).toEqual(['webauthn.assertion_failed']);
  });

  it('the refusal stays UNIFORM — the ledger gains detail the wire does not', async () => {
    // Recording must not become an oracle: all three branches answer the same
    // generic token, and only the trail tells them apart (by existing at all).
    const a = makeService({ challenge: null });
    const b = makeService({ credential: null });
    const first = await a.service
      .finishAuthentication(USER, SESSION, RESPONSE as never)
      .catch((e: unknown) => e);
    const second = await b.service
      .finishAuthentication(USER, SESSION, RESPONSE as never)
      .catch((e: unknown) => e);
    expect((first as HttpException).getResponse()).toEqual((second as HttpException).getResponse());
    expect((first as HttpException).getStatus()).toBe((second as HttpException).getStatus());
  });
});
