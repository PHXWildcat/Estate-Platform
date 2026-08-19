import { UnauthorizedException } from '@nestjs/common';
import {
  HANDOFF_AUDIENCES,
  HANDOFF_TTL_MS,
  HandoffService,
  type HandoffAudience,
} from '../src/handoff.service';
import type { EventsService } from '../src/events.service';
import type { HandoffRow, HandoffsRepo } from '../src/handoffs.repo';
import type { SessionsRepo } from '../src/sessions.repo';

/**
 * The handoff DECISIONS, with the repo faked.
 *
 * WHAT THIS LAYER PROVES AND WHAT IT DOES NOT, said out loud because this repo
 * has been caught before by a test named for a property it never touched. The
 * SQL — burn-on-attempt, expiry inside the UPDATE, the partial unique index —
 * is `handoffs.int.spec.ts`'s, and no fake repo can see it. What lives HERE is
 * everything the service decides between those statements: which audience is
 * threaded where, what a redeemed session is issued, and what is deliberately
 * NOT issued with it.
 *
 * It also runs without a database, which is why it exists at all: identity's
 * two handoff files were 0% functions in the no-Postgres CI pass, so every
 * property below was asserted only where a Postgres URL happened to be set.
 *
 * ONE PROPERTY IS DELIBERATELY NOT HERE, and saying so is the point. That the
 * refusal event carries no actor and no reason cannot be proven from this
 * layer: `handoffFailed()` takes zero arguments, so no fake of it can tell a
 * compliant emitter from a chatty one, and a mutation adding a reason to the
 * event passes every case below. It belongs to `events.service.ts` and is
 * proven in `handoff-events.spec.ts`. Found by mutating for it here and
 * watching nothing go red.
 */

const NOW = new Date('2026-08-18T12:00:00.000Z');

interface Recorded {
  inserts: Array<{ userId: string; audience: string; mintedFrom: string; expiresAt: Date }>;
  retired: string[];
  sessions: Array<Record<string, unknown>>;
  linked: Array<{ id: string; sessionId: string }>;
  events: Array<{ kind: string; detail?: unknown }>;
  /** One shared sequence, because ORDER is a property no per-call list holds. */
  order: string[];
}

function build(claim: HandoffRow | null = null): {
  service: HandoffService;
  rec: Recorded;
} {
  const rec: Recorded = {
    inserts: [],
    retired: [],
    sessions: [],
    linked: [],
    events: [],
    order: [],
  };

  const handoffs = {
    retireLive: (userId: string) => {
      rec.retired.push(userId);
      rec.order.push('retireLive');
      return Promise.resolve(1);
    },
    insert: (input: {
      userId: string;
      audience: string;
      mintedFrom: string;
      expiresAt: Date;
      codeSha256: Buffer;
    }) => {
      rec.order.push('insert');
      rec.inserts.push({
        userId: input.userId,
        audience: input.audience,
        mintedFrom: input.mintedFrom,
        expiresAt: input.expiresAt,
      });
      return Promise.resolve({} as HandoffRow);
    },
    claim: () => Promise.resolve(claim),
    recordSession: (id: string, sessionId: string) => {
      rec.linked.push({ id, sessionId });
      return Promise.resolve();
    },
  } as unknown as HandoffsRepo;

  const sessions = {
    create: (input: Record<string, unknown>) => {
      rec.sessions.push(input);
      return Promise.resolve();
    },
  } as unknown as SessionsRepo;

  const events = {
    handoffMinted: (_u: string, _s: string, detail: unknown) => {
      rec.events.push({ kind: 'minted', detail });
      return Promise.resolve();
    },
    handoffRedeemed: (_u: string, _s: string, detail: unknown) => {
      rec.events.push({ kind: 'redeemed', detail });
      return Promise.resolve();
    },
    handoffFailed: () => {
      rec.events.push({ kind: 'failed' });
      return Promise.resolve();
    },
  } as unknown as EventsService;

  return { service: new HandoffService(handoffs, sessions, events, () => NOW), rec };
}

function row(audience: HandoffAudience): HandoffRow {
  return {
    id: 'handoff-row-id',
    user_id: 'owner-user-id',
    audience,
    expires_at: new Date(NOW.getTime() + HANDOFF_TTL_MS),
    consumed_at: null,
  };
}

describe('HandoffService.mint', () => {
  it.each(HANDOFF_AUDIENCES)('threads %s through unchanged, and mints 160 bits', async (aud) => {
    // DERIVED FROM THE VOCABULARY, not listed: a third audience arrives with
    // this case already asserting it rather than with a test somebody has to
    // remember to add.
    const { service, rec } = build();
    const minted = await service.mint('owner-user-id', 'session-id', aud);

    expect(rec.inserts).toHaveLength(1);
    expect(rec.inserts[0]?.audience).toBe(aud);
    expect(rec.inserts[0]?.mintedFrom).toBe('session-id');
    // base64url of 20 bytes. The width is the security parameter — the same
    // 160 bits M13's link code and M14's verification code use.
    expect(Buffer.from(minted.code, 'base64url')).toHaveLength(20);
    expect(minted.expiresAt.getTime()).toBe(NOW.getTime() + HANDOFF_TTL_MS);
  });

  it('RETIRES BEFORE IT INSERTS, so two presses leave one live code', async () => {
    /*
     * ORDER IS THE PROPERTY, and asserting only that retirement HAPPENED would
     * be a test named for something it never touched: retire-after-insert
     * would kill the code it had just minted, and both spellings leave a
     * `retired` entry behind. So the two calls share one sequence.
     *
     * The retirement is also what makes `ux_auth_handoffs_live` satisfiable —
     * a partial index predicate cannot say "and not expired", so the write path
     * closes that invariant instead.
     */
    const { service, rec } = build();
    await service.mint('owner-user-id', 'session-id', 'operator');

    expect(rec.order).toEqual(['retireLive', 'insert']);
    expect(rec.retired).toEqual(['owner-user-id']);
    expect(rec.events[0]).toEqual({
      kind: 'minted',
      detail: { audience: 'operator', retired: 1 },
    });
  });

  it('RETIRES ACROSS AUDIENCES: an operator mint kills an outstanding vault code', async () => {
    // Deliberate, and it is the reason `retireLive` takes no audience: one
    // person at one keyboard is crossing to one origin, so a second live code
    // is a second thing to steal rather than a second thing to use.
    const { service, rec } = build();
    await service.mint('owner-user-id', 'session-id', 'vault');
    await service.mint('owner-user-id', 'session-id', 'operator');
    expect(rec.order).toEqual(['retireLive', 'insert', 'retireLive', 'insert']);
    expect(rec.inserts.map((i) => i.audience)).toEqual(['vault', 'operator']);
  });

  it('the code never appears in the audit detail', async () => {
    const { service, rec } = build();
    const minted = await service.mint('owner-user-id', 'session-id', 'vault');
    expect(JSON.stringify(rec.events)).not.toContain(minted.code);
  });
});

describe('HandoffService.redeem', () => {
  it.each(HANDOFF_AUDIENCES)(
    'is AUDIENCE-BLIND: it issues whatever the %s row says, never a default',
    async (aud) => {
      // The audience travels on the row that only the mint could write. If this
      // method ever grew an argument or a fallback, a redeem route that takes no
      // credential would be choosing what a session may reach.
      const { service, rec } = build(row(aud));
      const redeemed = await service.redeem('any-code');

      expect(rec.sessions[0]?.['audience']).toBe(aud);
      expect(redeemed.userId).toBe('owner-user-id');
      expect(rec.linked).toEqual([{ id: 'handoff-row-id', sessionId: redeemed.sessionId }]);
      expect(rec.events).toEqual([{ kind: 'redeemed', detail: { audience: aud } }]);
    },
  );

  it('issues NO refresh token and NO step-up, and dies with its access token', async () => {
    /*
     * The three subtractions that make a stolen code cheap, all asserted
     * together because each is invisible on its own.
     *
     * `refresh_token_h` is NOT NULL, so the row carries a digest — of a value
     * generated and dropped in the same expression. What matters is that it is
     * not the token handed back, so nothing anywhere can present it.
     *
     * And no step-up: the M15 PR4 escalation was a redeemed session arriving
     * step-up-fresh, which let a stolen 60-second code reach
     * `POST /v1/vault/reset` — gated on step-up ALONE — and crypto-shred a
     * vault with no vault password and no Secret Key.
     */
    const { service, rec } = build(row('operator'));
    const redeemed = await service.redeem('any-code');
    const created = rec.sessions[0] ?? {};

    expect(created['refreshTokenH']).toBeDefined();
    // `toEqual`, NOT `toBe`. `hashToken` returns a Buffer, and two Buffers with
    // identical bytes are different objects — so reference inequality is true
    // of the defect as well as of the fix. Caught by mutating the source to
    // `hashToken(accessToken)` and watching this case stay green.
    expect(created['refreshTokenH']).not.toEqual(created['accessTokenH']);
    expect(JSON.stringify(created)).not.toContain(redeemed.accessToken);
    expect(created['expiresAt']).toEqual(created['accessExpiresAt']);
    expect(Object.keys(created)).not.toContain('stepupExpiresAt');
    expect(Object.keys(created)).not.toContain('mfaLevel');
  });

  it('answers ONE refusal, with an event carrying no reason and no user', async () => {
    // Unknown, expired, spent and raced all arrive here as a null claim. A
    // trail that named which one fired would re-create through the audit
    // stream the oracle the uniform wire answer removes (M14 PR1).
    const { service, rec } = build(null);
    await expect(service.redeem('never-minted')).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(service.redeem('never-minted')).rejects.toMatchObject({
      response: { error: 'invalid_code' },
    });
    expect(rec.events).toEqual([{ kind: 'failed' }, { kind: 'failed' }]);
    expect(rec.sessions).toEqual([]);
  });
});
