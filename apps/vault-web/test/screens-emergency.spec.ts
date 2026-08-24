/**
 * @jest-environment jsdom
 */

/**
 * THE EMERGENCY-ACCESS SCREENS (M15 PR3).
 *
 * `emergency-crypto.spec.ts` proves the cryptography. This proves the things a
 * UI can get wrong on top of it, and every case here is one of those:
 *
 *   · The fingerprint ceremony is a REQUIRED human step, not a confirmation
 *     dialog. A screen that armed without it would silently remove the only
 *     defence against a server substituting its own key for a grantee's.
 *   · Denial is ONE TAP and never gated (docs/03 §5.2, the M6 rule that the
 *     protective action must never be harder than the permissive one).
 *   · M14's arming gate reads as a control firing, not as an outage (M9).
 *   · A grantee is never offered "open the vault" before the waiting period
 *     has actually elapsed.
 */
import 'fake-indexeddb/auto';
import {
  createEscrow,
  createServerEphemeral,
  generateRecoveryKeyPair,
  publicKeyFingerprint,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { installLifecycle, render } from '../src/client/app';
import { forgetSecretKey } from '../src/client/secret-key-store';

/**
 * THE STATUS VOCABULARY, READ OUT OF THE DDL RATHER THAN RETYPED HERE.
 *
 * The table below this used to be six hand-written rows under a comment saying
 * they were "pinned to `002_emergency_access.sql`" — which is the shape this
 * repo calls a test nobody runs: a claim about the tree asserted in prose. It
 * was also already wrong in the direction that matters. A seventh status added
 * to the CHECK would have been covered by the comment and by no assertion, and
 * an UNGATED status is a button offered where the service refuses or, worse,
 * withheld where the service allows — the exact M27 PR3a defect, which is that
 * `released` was collectable nowhere in this client because a hand-list said so.
 *
 * Reading it makes this spec's inputs reach outside its own package, so
 * `apps/vault-web/turbo.json` declares the canonical wide input set. Without
 * that, editing the CHECK constraint would not move this task's hash and the
 * one gate whose input just changed would replay a cached pass
 * (`packages/config/test/turbo-test-inputs.spec.ts` enforces the pairing).
 */
const POLICY_STATUSES: readonly string[] = (() => {
  const ddl = readFileSync(
    join(__dirname, '..', '..', 'services', 'vault', 'migrations', '002_emergency_access.sql'),
    'utf8',
  );
  const table = ddl.slice(ddl.indexOf('CREATE TABLE emergency_access_policies ('));
  const check = /status TEXT NOT NULL DEFAULT '[a-z_]+'\s*CHECK \(status IN \(([^)]*)\)\)/.exec(
    table,
  );
  if (!check) throw new Error('no status CHECK in 002_emergency_access.sql');
  return check[1]!.split(',').map((raw) => raw.trim().replace(/^'|'$/g, ''));
})();

const USER = '11111111-2222-4333-8444-555555555555';
const GRANTEE = '22222222-3333-4444-8555-666666666666';
const PASSWORD = 'a-good-vault-password';

interface Service {
  calls: Array<{ path: string; method: string; body: string }>;
  /** Forced failures, keyed `METHOD /path`. */
  fail: Map<string, { status: number; error: string }>;
  candidates: Array<{ contactId: string; userId: string; name: string }>;
  escrow: { configured: boolean; threshold: number | null; policies: unknown[] };
  grantedToMe: unknown[];
  /** Whether this user has published a recovery key of their own. */
  ownKey: { publicKey: string; wrappedPrivateKey: string } | null;
  /** A published key for anyone the owner might name. */
  publishedKeys: Map<string, string>;
  /**
   * What a release hands back. Built by the test playing the OWNER's device,
   * so the grantee side runs against a real escrow rather than a fixture.
   */
  release: { status: number; body: unknown } | null;
}

function installService(): Service {
  const state: Service = {
    calls: [],
    fail: new Map(),
    candidates: [],
    escrow: { configured: false, threshold: null, policies: [] },
    grantedToMe: [],
    ownKey: null,
    publishedKeys: new Map(),
    release: null,
  };
  let keyset: Record<string, string> | null = null;
  let ephemeral: Awaited<ReturnType<typeof createServerEphemeral>> | null = null;

  const reply = (status: number, payload: unknown): unknown => ({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  });

  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET';
    const body = typeof init.body === 'string' ? init.body : '';
    state.calls.push({ path, method, body });

    const forced = state.fail.get(`${method} ${path.split('?')[0] as string}`);
    if (forced) return Promise.resolve(reply(forced.status, { error: forced.error }));

    if (path === '/api/auth/session') {
      return Promise.resolve(reply(200, { userId: USER, audience: 'vault' }));
    }
    if (path === '/api/vault/keyset' && method === 'GET') {
      return Promise.resolve(reply(200, { enrolled: keyset !== null, updatedAt: null }));
    }
    if (path === '/api/vault/keyset' && method === 'POST') {
      keyset = JSON.parse(body) as Record<string, string>;
      return Promise.resolve(reply(201, { enrolled: true, updatedAt: null }));
    }
    if (path === '/api/vault/srp/start') {
      if (!keyset) return Promise.resolve(reply(404, { error: 'keyset_not_found' }));
      return createServerEphemeral(
        decodeGroupElement(keyset['srpVerifier'] as string, 'verifier'),
      ).then((made) => {
        ephemeral = made;
        return reply(201, {
          handshakeId: '00000000-0000-4000-8000-000000000000',
          srpSalt: keyset?.['srpSalt'],
          kdfParams: keyset?.['kdfParams'],
          serverPublic: encodeGroupElement(made.B),
        });
      });
    }
    if (path === '/api/vault/srp/verify') {
      if (!keyset || !ephemeral) return Promise.resolve(reply(401, { error: 'srp_failed' }));
      const parsed = JSON.parse(body) as Record<string, string>;
      return verifyClientSession({
        userId: USER,
        salt: fromBase64(keyset['srpSalt'] as string),
        verifier: decodeGroupElement(keyset['srpVerifier'] as string, 'verifier'),
        ephemeral,
        A: decodeGroupElement(parsed['clientPublic'] as string, 'client public value'),
        M1: fromBase64(parsed['clientProof'] as string),
      }).then((verified) =>
        verified
          ? reply(200, {
              serverProof: toBase64(verified.M2),
              wrappedMasterKey: keyset?.['wrappedMasterKey'],
              vaultSession: {
                id: '11111111-0000-4000-8000-000000000000',
                token: 'opaque-vault-session-token',
                expiresAt: '2099-01-01T00:00:00.000Z',
              },
            })
          : reply(401, { error: 'srp_failed' }),
      );
    }
    if (path.startsWith('/api/vault/items')) {
      return Promise.resolve(reply(200, { items: [], nextCursor: null }));
    }
    if (path === '/api/grantee-candidates') {
      return Promise.resolve(reply(200, { candidates: state.candidates }));
    }
    if (path === '/api/vault/recovery-key' && method === 'POST') {
      const parsed = JSON.parse(body) as Record<string, string>;
      state.ownKey = {
        publicKey: parsed['publicKey'] as string,
        wrappedPrivateKey: parsed['wrappedPrivateKey'] as string,
      };
      return Promise.resolve(reply(201, { status: 'ok' }));
    }
    if (path === '/api/vault/recovery-key' && method === 'GET') {
      return Promise.resolve(
        state.ownKey ? reply(200, state.ownKey) : reply(404, { error: 'recovery_key_not_found' }),
      );
    }
    if (path.startsWith('/api/vault/recovery-key/')) {
      const target = path.split('/').pop() as string;
      const published = state.publishedKeys.get(target);
      return Promise.resolve(
        published
          ? reply(200, { granteeUserId: target, publicKey: published })
          : reply(404, { error: 'recovery_key_not_found' }),
      );
    }
    if (path.endsWith('/release')) {
      // THE DEFAULT REFUSAL IS ONE THE SERVICE CAN STILL SEND. It was 409
      // `already_released` until M27 PR3a made collection repeatable, at which
      // point this fake became the last thing in the repo enforcing a rule the
      // real route had dropped — and the screen test below went on passing
      // against a server that no longer exists. `not_requested` is what a
      // release with no elapsed `releases_at` actually answers.
      return Promise.resolve(
        state.release
          ? reply(state.release.status, state.release.body)
          : reply(409, { error: 'not_requested' }),
      );
    }
    if (path === '/api/vault/emergency-access' && method === 'GET') {
      return Promise.resolve(reply(200, state.escrow));
    }
    if (path === '/api/vault/emergency-access/granted-to-me') {
      return Promise.resolve(reply(200, state.grantedToMe));
    }
    if (path === '/api/vault/emergency-access' && method === 'POST') {
      // Faithful to the real service: it answers with the policies it just
      // created, one per grantee, so the screen re-renders against reality.
      const parsed = JSON.parse(body) as {
        threshold: number;
        grantees: Array<Record<string, unknown>>;
      };
      state.escrow = {
        configured: true,
        threshold: parsed.threshold,
        policies: parsed.grantees.map((g, index) => ({
          id: `p${index + 1}`,
          granteeContactId: g['granteeContactId'],
          granteeUserId: g['granteeUserId'],
          waitingPeriodHours: g['waitingPeriodHours'],
          status: 'configured',
          requestedAt: null,
          releasesAt: null,
          requestCount: 0,
        })),
      };
      return Promise.resolve(reply(201, state.escrow));
    }
    return Promise.resolve(reply(200, {}));
  }) as unknown as typeof fetch;

  return state;
}

function mount(): void {
  const root = document.createElement('main');
  root.setAttribute('id', 'app');
  document.body.replaceChildren(root);
  window.ESTATE_APP_ORIGIN = 'http://localhost:3000';
}

const byLabel = (label: string): HTMLInputElement => {
  const id = [...document.querySelectorAll('label')]
    .find((l) => l.textContent?.includes(label))
    ?.getAttribute('for');
  const node = id ? document.getElementById(id) : null;
  if (!node) throw new Error(`no field labelled ${label}. Saw: ${document.body.textContent}`);
  return node as HTMLInputElement;
};

const findButton = (text: string): HTMLButtonElement | undefined =>
  [...document.querySelectorAll('button')].find((b) => b.textContent?.includes(text));

const clickText = (text: string): void => {
  const button = findButton(text);
  if (!button) throw new Error(`no button "${text}". Saw: ${document.body.textContent}`);
  button.click();
};

const submitForm = (index = 0): void => {
  const form = document.querySelectorAll('form')[index];
  form?.dispatchEvent(new Event('submit', { cancelable: true }));
};

/**
 * SUBMIT THE STEP-UP PROMPT BY THE FORM THAT OWNS ITS FIELD.
 *
 * The prompt renders into a `<div>` inside the form of the action it guards, so
 * the step-up form is NESTED — and the ancestor's `querySelector('#stepup-code')`
 * finds it too. Selecting "every form CONTAINING the field" therefore matched
 * both and submitted the guarded action a SECOND time, unawaited. That is what
 * made `screens-stepup.spec.ts` fail intermittently on CI; the same loop was
 * here, and the same targeting fixes it. `input.form` is the HTML form owner —
 * the nearest ancestor form, which is the prompt's own.
 */
const submitStepUp = (code = '123456'): void => {
  const input = document.getElementById('stepup-code') as HTMLInputElement | null;
  if (!input) throw new Error(`no step-up prompt. Saw: ${document.body.textContent}`);
  input.value = code;
  input.form?.dispatchEvent(new Event('submit', { cancelable: true }));
};

const waitForText = async (pattern: string | RegExp, deadlineMs = 30_000): Promise<void> => {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const text = document.body.textContent ?? '';
    if (typeof pattern === 'string' ? text.includes(pattern) : pattern.test(text)) return;
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${String(pattern)}. Saw: ${text.slice(0, 600)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

/** A real enrollment and a real SRP unlock, then the emergency screen. */
async function openEmergency(): Promise<void> {
  await render();
  await waitForText('Set up your vault');
  byLabel('Vault password').value = PASSWORD;
  byLabel('Confirm vault password').value = PASSWORD;
  submitForm();
  await waitForText('Save your Secret Key');
  (document.getElementById('ack') as HTMLInputElement).checked = true;
  clickText('I have saved it');
  await waitForText('Unlock your vault');
  byLabel('Vault password').value = PASSWORD;
  submitForm();
  await waitForText(/nothing here yet/i);
  clickText('Emergency access');
  await waitForText('Your arrangement');
}

describe('the emergency-access screens', () => {
  jest.setTimeout(180_000);

  beforeEach(() => {
    mount();
  });

  afterEach(async () => {
    await forgetSecretKey(USER);
  });

  it('refuses to arm before a single fingerprint has been confirmed', async () => {
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    await openEmergency();
    await waitForText('Ada');

    clickText('Arm emergency access');
    await waitForText(/confirm at least one/i);
    // Nothing was armed, and nothing was even attempted.
    expect(
      service.calls.filter((c) => c.method === 'POST' && c.path === '/api/vault/emergency-access'),
    ).toHaveLength(0);
  });

  it('shows the fingerprint to read out, and only then lets the owner arm', async () => {
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    await openEmergency();
    await waitForText('Ada');

    clickText('Confirm key');
    await waitForText(/by phone or in person/i);
    await waitForText('key confirmed');
    // 80 bits in the M6-widened alphabet, which is the security parameter of
    // the whole ceremony — a fingerprint short enough to skim is a fingerprint
    // an attacker can collide.
    const shown = [...document.querySelectorAll('.secret-key')].at(-1)?.textContent ?? '';
    expect(shown.replace(/-/g, '')).toHaveLength(16);

    clickText('Arm emergency access');
    await waitForText(/1 contact\(s\) named/i);
    const armed = service.calls.find(
      (c) => c.method === 'POST' && c.path === '/api/vault/emergency-access',
    );
    // What crossed the wire is a sealed share and a platform half — never a key.
    expect(armed?.body).toContain('platformPart');
    expect(armed?.body).toContain('granteePublicKeySha256');
  });

  it('refuses a key it cannot parse rather than hanging on it', async () => {
    // The server is hostile in Zone A's threat model, so a malformed
    // `publicKey` is an expected input. Without this the row sat on "not
    // confirmed" forever and the owner had nothing to act on.
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    service.publishedKeys.set(GRANTEE, 'not-a-key');
    await openEmergency();
    await waitForText('Ada');

    clickText('Confirm key');
    await waitForText(/not accepted/i);
    expect(document.body.textContent).not.toContain('key confirmed');
  });

  it('tells the owner nobody can name them until they publish a key', async () => {
    const service = installService();
    service.ownKey = null;
    await openEmergency();
    await waitForText(/nobody can name you for emergency access yet/i);
    expect(findButton('Let others name me')).toBeDefined();

    clickText('Let others name me');
    await waitForText(/your key is published/i);
    expect(service.ownKey).not.toBeNull();
    // The private half went up WRAPPED, never in the clear.
    const published = service.calls.find(
      (c) => c.method === 'POST' && c.path === '/api/vault/recovery-key',
    );
    expect(published?.body).toContain('wrappedPrivateKey');
  });

  it('reads M14’s arming gate as a control firing, not as an outage', async () => {
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    service.fail.set('POST /api/vault/emergency-access', {
      status: 503,
      error: 'recipient_unverified',
    });
    await openEmergency();
    await waitForText('Ada');
    clickText('Confirm key');
    await waitForText('key confirmed');
    clickText('Arm emergency access');

    await waitForText(/confirm your email address in estate/i);
    // The M9 rule: a control firing must not read as an outage. "Try again
    // shortly" would send the owner round a loop that can never complete.
    expect(document.body.textContent).not.toMatch(/temporarily unreachable/i);
  });

  it('keeps a notifications OUTAGE distinct from that gate', async () => {
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    service.fail.set('POST /api/vault/emergency-access', {
      status: 503,
      error: 'notifications_unavailable',
    });
    await openEmergency();
    await waitForText('Ada');
    clickText('Confirm key');
    await waitForText('key confirmed');
    clickText('Arm emergency access');

    await waitForText(/cannot send notifications right now/i);
    expect(document.body.textContent).not.toMatch(/confirm your email address/i);
  });

  it('offers one-tap denial on a waiting request, and never a challenge', async () => {
    const service = installService();
    service.escrow = {
      configured: true,
      threshold: 1,
      policies: [
        {
          id: 'p1',
          granteeContactId: 'c1',
          granteeUserId: GRANTEE,
          waitingPeriodHours: 48,
          status: 'waiting',
          requestedAt: '2026-08-08T00:00:00.000Z',
          releasesAt: '2099-01-01T00:00:00.000Z',
          requestCount: 1,
        },
      ],
    };
    await openEmergency();
    await waitForText(/waiting period running/i);

    const stop = findButton('Stop this');
    expect(stop).toBeDefined();
    // The permissive direction is the gated one. Re-arming a denied policy is
    // step-up gated server-side; stopping one is not, and must not be offered
    // as though it were.
    expect(findButton('Allow again')).toBeUndefined();

    stop?.click();
    await waitForText(/that request cannot proceed/i);
    expect(
      service.calls.some(
        (c) => c.method === 'POST' && c.path === '/api/vault/emergency-access/p1/deny',
      ),
    ).toBe(true);
  });

  it('offers re-arming only once a policy has been denied', async () => {
    const service = installService();
    service.escrow = {
      configured: true,
      threshold: 1,
      policies: [
        {
          id: 'p1',
          granteeContactId: 'c1',
          granteeUserId: GRANTEE,
          waitingPeriodHours: 48,
          status: 'denied_by_owner',
          requestedAt: null,
          releasesAt: null,
          requestCount: 2,
        },
      ],
    };
    await openEmergency();
    await waitForText(/stopped by you/i);
    expect(findButton('Allow again')).toBeDefined();
    // Denial is STICKY with no cooldown (M6): there is nothing to stop, because
    // nothing is running.
    expect(findButton('Stop this')).toBeUndefined();
  });

  it('does not offer a grantee the vault before the waiting period has elapsed', async () => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'waiting',
        releasesAt: new Date(Date.now() + 36 * 3_600_000).toISOString(),
      },
    ];
    await openEmergency();
    await waitForText(/waiting — about/i);
    expect(findButton('Open the vault')).toBeUndefined();
    // And an armed policy offers the request, which starts the clock and grants
    // nothing by itself.
    expect(findButton('Request access')).toBeUndefined();
  });

  it('offers the release only once the clock has actually run out', async () => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
      },
    ];
    await openEmergency();
    await waitForText(/ready to open/i);
    expect(findButton('Open the vault')).toBeDefined();
  });

  it('renders a failed read as a failure, never as “nobody is arranged”', async () => {
    const service = installService();
    service.fail.set('GET /api/vault/emergency-access', { status: 503, error: 'unavailable' });
    await openEmergency();
    await waitForText(/temporarily unreachable/i);
    // Saying "nobody can open this vault but you" over a failed read would tell
    // an owner their arrangement is gone.
    expect(document.body.textContent).not.toMatch(/nobody can open this vault but you/i);
  });

  it('sends the user to unlock rather than blanking, if the vault locked meanwhile', async () => {
    // The screen's reads all need an open vault, and the lock can fire while it
    // is on screen — bfcache restore, idle timeout. A thrown accessor on the
    // re-read would leave an empty page in front of someone mid-emergency.
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'configured',
        releasesAt: null,
      },
    ];
    installLifecycle();
    await openEmergency();
    await waitForText(/ready if they cannot/i);

    window.dispatchEvent(new Event('pagehide')); // locks
    clickText('Request access');
    await waitForText('Unlock your vault');
    expect(document.body.textContent).not.toMatch(/your arrangement/i);
  });

  it('refuses a waiting period under 24 hours, before anything is sent', async () => {
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    await openEmergency();
    await waitForText('Ada');
    clickText('Confirm key');
    await waitForText('key confirmed');

    byLabel('Waiting period (hours)').value = '1';
    clickText('Arm emergency access');
    await waitForText(/at least 24 hours/i);
    // A one-hour delay is not a control: docs/03 §5.2's whole point is that the
    // owner has time to notice and stop it.
    expect(
      service.calls.filter((c) => c.method === 'POST' && c.path === '/api/vault/emergency-access'),
    ).toHaveLength(0);
  });

  it('refuses a threshold larger than the number of confirmed grantees', async () => {
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    await openEmergency();
    await waitForText('Ada');
    clickText('Confirm key');
    await waitForText('key confirmed');

    byLabel('How many must act together').value = '3';
    clickText('Arm emergency access');
    // 3-of-1 would arm an escrow nobody could ever open, and the owner would
    // believe they had arranged something.
    await waitForText(/choose between 1 and 1/i);
    expect(
      service.calls.filter((c) => c.method === 'POST' && c.path === '/api/vault/emergency-access'),
    ).toHaveLength(0);
  });

  it('says plainly when there is nobody to name yet', async () => {
    const service = installService();
    service.candidates = [];
    await openEmergency();
    await waitForText(/none of your contacts has an estate account linked/i);
    // No picker, so no arm button that could not work.
    expect(findButton('Arm emergency access')).toBeUndefined();
  });

  it('reports a contacts failure as a failure, not as “nobody to name”', async () => {
    const service = installService();
    service.fail.set('GET /api/grantee-candidates', { status: 502, error: 'contacts_unavailable' });
    await openEmergency();
    await waitForText(/could not load your contacts/i);
    expect(document.body.textContent).not.toMatch(/none of your contacts has an estate account/i);
  });

  it('reports a granted-to-me failure without claiming nobody named you', async () => {
    const service = installService();
    service.fail.set('GET /api/vault/emergency-access/granted-to-me', {
      status: 503,
      error: 'unavailable',
    });
    await openEmergency();
    await waitForText(/could not check what others have named you for/i);
    expect(document.body.textContent).not.toMatch(/nobody has named you for emergency access/i);
  });

  it('removes an arrangement, and surfaces a refusal rather than pretending', async () => {
    const service = installService();
    const armed = {
      id: 'p1',
      granteeContactId: 'c1',
      granteeUserId: GRANTEE,
      waitingPeriodHours: 48,
      status: 'configured',
      requestedAt: null,
      releasesAt: null,
      requestCount: 0,
    };
    service.escrow = { configured: true, threshold: 1, policies: [armed] };
    service.fail.set('DELETE /api/vault/emergency-access/p1', {
      status: 403,
      error: 'stepup_required',
    });
    await openEmergency();
    await waitForText(/ready if you cannot/i);

    clickText('Remove');
    // Revocation IS step-up gated server-side (it destroys a grantee's only
    // route in), so the screen has to say what to do about it.
    await waitForText(/fresh identity check/i);
    expect(service.escrow.policies).toHaveLength(1);
  });

  it('lets a grantee start the clock, and says what that did', async () => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'configured',
        releasesAt: null,
      },
    ];
    await openEmergency();
    await waitForText(/ready if they cannot/i);

    clickText('Request access');
    await waitForText(/waiting period has started and the owner has been told/i);
    expect(
      service.calls.some(
        (c) => c.method === 'POST' && c.path === '/api/vault/emergency-access/p9/request',
      ),
    ).toBe(true);
  });

  it('reconstructs the owner’s key in the browser, from a real sealed escrow', async () => {
    // THE GRANTEE SIDE, END TO END THROUGH THE UI. The test plays the owner's
    // device: it seals a share to the key this browser publishes, exactly as
    // `configureEscrow` would, and the screen then opens it with the private
    // half that lives inside this vault.
    const service = installService();
    await openEmergency();
    await waitForText(/nobody can name you for emergency access yet/i);
    clickText('Let others name me');
    await waitForText(/your key is published/i);

    const ownerMasterKey = crypto.getRandomValues(new Uint8Array(32));
    const OWNER_ID = '33333333-4444-4555-8666-777777777777';
    const material = await createEscrow({
      ownerUserId: OWNER_ID,
      masterKey: ownerMasterKey,
      grantees: [{ granteeUserId: USER, publicKey: fromBase64(service.ownKey?.publicKey ?? '') }],
      threshold: 1,
    });
    service.release = {
      status: 200,
      body: {
        ownerUserId: OWNER_ID,
        platformPart: material.platformPart,
        wrappedMasterKeyRecovery: material.wrappedMasterKeyRecovery,
        keyShare: material.shares[0]?.sealedShare,
        threshold: material.threshold,
      },
    };
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
      },
    ];

    // Re-enter the screen so it picks up the new granted-to-me state.
    clickText('Back');
    await waitForText(/nothing here yet/i);
    clickText('Emergency access');
    await waitForText('Your arrangement');
    await waitForText(/ready to open/i);

    clickText('Open the vault');
    // The warning gate, staged on the sentence that SURVIVED M27 PR3a rather
    // than the single-use claim that did not. Its own assertions live in
    // `warns before a collection WITHOUT claiming it is the only one`; this
    // one only needs to know the screen arrived.
    await waitForText(/only continue if they genuinely cannot/i);
    clickText('Open it now');
    await waitForText(/reconstructed on this device/i);
    // And it stays on the device: nothing carries a recovered key back up.
    expect(
      service.calls.filter((c) => c.method === 'POST' && c.body.includes('masterKey')),
    ).toHaveLength(0);
  });

  it('tells a locked-out grantee to unlock their OWN vault, not the owner’s', async () => {
    const service = installService();
    service.ownKey = null;
    service.fail.set('GET /api/vault/recovery-key', { status: 403, error: 'vault_locked' });
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
      },
    ];
    await openEmergency();
    await waitForText(/ready to open/i);
    clickText('Open the vault');
    clickText('Open it now');
    await waitForText(/unlock your own vault first/i);
  });

  /**
   * THE LAST THING READ BEFORE THE DECISION, AND NOTHING ASSERTED IT.
   *
   * `renderRelease`'s two warnings told the grantee the arrangement was
   * single-use and would be consumed by continuing. Correct in M15, false
   * since M27 PR3a, and this screen is where somebody in a real emergency
   * decides whether to act — so a stale sentence here is the one that changes
   * behaviour rather than merely reading oddly. It survived a source sweep
   * because it made the claim in a third wording, and it survived the suite
   * because no test looked at this screen's copy at all. Both halves are
   * closed: `fences.spec.ts` bans the spellings as data, and this asserts the
   * two things the sentence must still carry.
   */
  it('warns before a collection WITHOUT claiming it is the only one', async () => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
      },
    ];
    await openEmergency();
    await waitForText(/ready to open/i);
    clickText('Open the vault');
    await waitForText(/only continue if they genuinely cannot/i);

    const warning = document.body.textContent ?? '';
    // WHAT MUST STILL BE SAID. The owner-is-told sentence is the compensating
    // control the whole change rests on, so losing it would quietly remove the
    // reason re-collection is safe.
    expect(warning).toMatch(/the owner is told every time/i);
    // And the honest limit is unchanged: this does not read their items.
    expect(warning).toMatch(/not built yet/i);

    // WHAT MUST NOT BE SAID, asserted on this rendered screen rather than only
    // on the source, so a reworded relapse is caught where a reader would meet
    // it. The claim, in each spelling the code has actually used.
    expect(warning).not.toMatch(/spends the arrangement/i);
    expect(warning).not.toMatch(/can be done once/i);
    expect(warning).not.toMatch(/used a second time/i);
    // ANTI-VACUITY: this really is the release confirmation and not a screen
    // that happens to lack those words. A blank page passes every `not.toMatch`.
    expect(warning).toMatch(/open the vault you were trusted with/i);
  });

  it('does not claim a release worked when the service refused it', async () => {
    const service = installService();
    await openEmergency();
    clickText('Let others name me');
    await waitForText(/your key is published/i);
    service.release = null; // the fake answers 409 not_requested
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
      },
    ];
    clickText('Back');
    await waitForText(/nothing here yet/i);
    clickText('Emergency access');
    await waitForText('Your arrangement');
    await waitForText(/ready to open/i);
    clickText('Open the vault');
    clickText('Open it now');
    await waitForText(/changed since you opened it/i);
    expect(document.body.textContent).not.toMatch(/reconstructed on this device/i);
  });

  it('names the PERSON in an arrangement, never their account id', async () => {
    // Found by driving the live stack: the row printed a bare UUID, so an owner
    // reading their own arrangement could not tell who they had named — which
    // is the only reason to read it back at all. The candidate list is the only
    // place a name exists on this origin.
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada Grantee' }];
    service.escrow = {
      configured: true,
      threshold: 1,
      policies: [
        {
          id: 'p1',
          granteeContactId: 'c1',
          granteeUserId: GRANTEE,
          waitingPeriodHours: 48,
          status: 'configured',
          requestedAt: null,
          releasesAt: null,
          requestCount: 0,
        },
      ],
    };
    await openEmergency();
    await waitForText('Ada Grantee');
    // And the status is words, not the schema enum the service stores.
    await waitForText(/ready if you cannot · 48h wait/i);
    expect(document.body.textContent).not.toContain(GRANTEE);
  });

  it('falls back to the account id when the contact is gone, rather than hiding the row', async () => {
    // A deleted contact must not make a LIVE arrangement disappear: the escrow
    // is still armed and the owner still has to be able to remove it.
    const service = installService();
    service.candidates = [];
    service.escrow = {
      configured: true,
      threshold: 1,
      policies: [
        {
          id: 'p1',
          granteeContactId: 'c1',
          granteeUserId: GRANTEE,
          waitingPeriodHours: 48,
          status: 'configured',
          requestedAt: null,
          releasesAt: null,
          requestCount: 0,
        },
      ],
    };
    await openEmergency();
    await waitForText(GRANTEE);
    expect(findButton('Remove')).toBeDefined();
  });

  it('renders an UNKNOWN status rather than blanking the row', async () => {
    // A service deployed ahead of this origin must not empty the page — the M12
    // rule. The raw token is at least true.
    const service = installService();
    service.escrow = {
      configured: true,
      threshold: 1,
      policies: [
        {
          id: 'p1',
          granteeContactId: 'c1',
          granteeUserId: GRANTEE,
          waitingPeriodHours: 48,
          status: 'some_future_state',
          requestedAt: null,
          releasesAt: null,
          requestCount: 0,
        },
      ],
    };
    await openEmergency();
    await waitForText(/some future state/i);
  });

  /**
   * EVERY STATUS THE DDL CAN HOLD, AGAINST WHAT EACH SCREEN OFFERS.
   *
   * Three tables, one corpus. Each is keyed by the status set parsed out of
   * `002_emergency_access.sql`, and each asserts SET EQUALITY with it before
   * reading a single button — the anti-vacuity floor, at the level that
   * matters rather than only on a total. A row added to the CHECK constraint
   * fails these three tests by name until somebody decides what the screens do
   * with it, which is the decision that was skipped when `released` became
   * collectable server-side and stayed unofferable here.
   */
  const EXPECTATIONS = {
    request: {
      // Gating on an invented `armed` meant the button could never appear — the
      // defect the live stack found, and the reason this is DDL-derived now.
      configured: true,
      requested: true,
      waiting: false,
      denied_by_owner: false,
      released: false,
      revoked: false,
    },
    // "Open the vault", for a policy whose waiting period has ALREADY elapsed.
    // `released` is the M27 PR3a row: the service admits
    // `status IN ('waiting','released')` with an elapsed `releases_at`, and
    // before PR3a this client offered it on the first of those only — so the
    // grantee whose collection was interrupted saw the word "opened" and no
    // control, in the one scenario §5.2 exists for.
    open: {
      configured: false,
      requested: false,
      waiting: true,
      denied_by_owner: false,
      released: true,
      revoked: false,
    },
    // The OWNER's controls. `released` carried NONE of these before PR3a —
    // deny was gated on `waiting`, revoke on `!== 'released'` — which made the
    // status where the grantee can collect with one tap the only status where
    // the owner could do nothing at all. docs/03's rule points the other way.
    ownerStops: {
      configured: { stop: false, remove: true },
      requested: { stop: false, remove: true },
      waiting: { stop: true, remove: true },
      denied_by_owner: { stop: false, remove: true },
      released: { stop: true, remove: true },
      revoked: { stop: false, remove: true },
    },
  } as const;

  it('covers EVERY status in the DDL, in all three tables', () => {
    // The floor. Any of these tables silently narrowing is how a status stops
    // being considered without anybody noticing, so the corpus is compared as a
    // SET against the CHECK constraint rather than by length.
    const ddl = [...POLICY_STATUSES].sort();
    expect(ddl.length).toBeGreaterThan(0);
    expect(Object.keys(EXPECTATIONS.request).sort()).toEqual(ddl);
    expect(Object.keys(EXPECTATIONS.open).sort()).toEqual(ddl);
    expect(Object.keys(EXPECTATIONS.ownerStops).sort()).toEqual(ddl);
  });

  it('offers the request on every status the service would actually accept', async () => {
    for (const status of POLICY_STATUSES) {
      mount();
      const service = installService();
      service.grantedToMe = [
        {
          id: 'p9',
          ownerUserId: '33333333-4444-4555-8666-777777777777',
          status,
          releasesAt: null,
        },
      ];
      await openEmergency();
      await waitForText('Granted to you');
      expect({ status, offered: findButton('Request access') !== undefined }).toEqual({
        status,
        offered: EXPECTATIONS.request[status as keyof typeof EXPECTATIONS.request],
      });
      await forgetSecretKey(USER);
    }
  });

  it('offers COLLECTION on every status the service would release on', async () => {
    const elapsed = new Date(Date.now() - 60_000).toISOString();
    for (const status of POLICY_STATUSES) {
      mount();
      const service = installService();
      service.grantedToMe = [
        {
          id: 'p9',
          ownerUserId: '33333333-4444-4555-8666-777777777777',
          status,
          // Elapsed for EVERY row, so the only variable is the status. A null
          // here would make the table pass for the wrong reason on all six.
          releasesAt: elapsed,
        },
      ];
      await openEmergency();
      await waitForText('Granted to you');
      expect({ status, offered: findButton('Open the vault') !== undefined }).toEqual({
        status,
        offered: EXPECTATIONS.open[status as keyof typeof EXPECTATIONS.open],
      });
      await forgetSecretKey(USER);
    }
  });

  /**
   * WHAT THE GRANTEE IS TOLD, on every status the DDL can hold.
   *
   * `POLICY_STATUS_WORDS` is the OWNER's vocabulary and this list is read by
   * the other person, so a word that is true for one can be a false sentence
   * about the other. Found by driving the stack: a denied row told the grantee
   * "stopped by you" — the owner stopped it — on the row explaining why their
   * button had gone. The fourth table keyed on the same DDL corpus, because
   * the defect was an entry nobody asked about, and asking about all six is
   * the only way that does not recur.
   */
  const GRANTEE_WORDS: Readonly<Record<string, RegExp>> = {
    configured: /ready if they cannot/i,
    requested: /requested/i,
    waiting: /ready to open/i,
    denied_by_owner: /stopped by the owner/i,
    released: /opened — you can open it again/i,
    revoked: /removed/i,
  };

  it('never tells the grantee a sentence that is only true of the OWNER', async () => {
    expect(Object.keys(GRANTEE_WORDS).sort()).toEqual([...POLICY_STATUSES].sort());
    const elapsed = new Date(Date.now() - 60_000).toISOString();
    for (const status of POLICY_STATUSES) {
      mount();
      const service = installService();
      service.grantedToMe = [
        {
          id: 'p9',
          ownerUserId: '33333333-4444-4555-8666-777777777777',
          status,
          releasesAt: elapsed,
        },
      ];
      await openEmergency();
      await waitForText('Granted to you');
      const shown = document.body.textContent ?? '';
      expect({ status, ok: GRANTEE_WORDS[status]!.test(shown) }).toEqual({ status, ok: true });
      // THE OWNER'S TWO SECOND-PERSON WORDINGS MUST NOT REACH THIS READER.
      // Asserted on every row rather than only the two that were wrong, so a
      // future entry that borrows either spelling is caught here.
      expect(shown).not.toMatch(/stopped by you/i);
      expect(shown).not.toMatch(/ready if you cannot/i);
      await forgetSecretKey(USER);
    }
  });

  it('offers the owner a STOP on every status a grantee can still act on', async () => {
    const elapsed = new Date(Date.now() - 60_000).toISOString();
    for (const status of POLICY_STATUSES) {
      mount();
      const service = installService();
      service.escrow = {
        configured: true,
        threshold: 1,
        policies: [
          {
            id: 'p1',
            granteeContactId: 'c1',
            granteeUserId: GRANTEE,
            waitingPeriodHours: 48,
            status,
            requestedAt: null,
            releasesAt: elapsed,
            requestCount: 0,
          },
        ],
      };
      await openEmergency();
      await waitForText(GRANTEE);
      const expected = EXPECTATIONS.ownerStops[status as keyof typeof EXPECTATIONS.ownerStops];
      // Both spellings of the stop count: 'Stop this' on a waiting request and
      // 'Stop further access' on a released one are the same control saying a
      // true sentence about two different situations.
      const stop =
        findButton('Stop this') !== undefined || findButton('Stop further access') !== undefined;
      expect({ status, stop, remove: findButton('Remove') !== undefined }).toEqual({
        status,
        ...expected,
      });
      await forgetSecretKey(USER);
    }
  });

  it('shows the grantee their OWN fingerprint, so the ceremony can be completed', async () => {
    /*
     * The M15 review's highest finding: the owner is told to read a fingerprint
     * to the grantee, and the grantee had nowhere to read theirs. A ceremony
     * only one side can perform is not a defence against key substitution.
     */
    const service = installService();
    await openEmergency();
    await waitForText(/nobody can name you for emergency access yet/i);
    clickText('Let others name me');
    await waitForText(/your key is published/i);

    await waitForText(/check it against yours/i);
    const shown = [...document.querySelectorAll('.secret-key')].at(-1)?.textContent ?? '';
    expect(shown.replace(/-/g, '')).toHaveLength(16);
    // And it is the fingerprint of the key the SERVER holds, which is the value
    // an owner naming this person would be shown.
    expect(shown).toBe(await publicKeyFingerprint(fromBase64(service.ownKey?.publicKey ?? '')));
  });

  it('refuses to arm a threshold this client could never open', async () => {
    // The service and vault-crypto both do M-of-N; `releaseAndRecover` passes a
    // single share, so arming 2-of-2 would store an arrangement nobody can open
    // and the first grantee to try would spend their one-shot policy on it.
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    await openEmergency();
    await waitForText('Ada');
    clickText('Confirm key');
    await waitForText('key confirmed');

    byLabel('How many must act together').value = '2';
    clickText('Arm emergency access');
    await waitForText(/choose between 1 and 1/i);
    expect(
      service.calls.filter((c) => c.method === 'POST' && c.path === '/api/vault/emergency-access'),
    ).toHaveLength(0);
  });

  it('reports a failure to read the published key back rather than showing a wrong one', async () => {
    // Refusing to display SOMETHING is the right answer: a fingerprint computed
    // from a key we could not parse, compared against the owner's, would
    // confirm a substitution as legitimate.
    const service = installService();
    service.ownKey = { publicKey: 'not-a-key', wrappedPrivateKey: 'also-not' };
    await openEmergency();
    await waitForText(/could not read your key.s fingerprint back/i);
    expect(document.querySelectorAll('.secret-key')).toHaveLength(0);
  });

  it('surfaces a request refused by M14’s arming gate on the GRANTEE side too', async () => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: '33333333-4444-4555-8666-777777777777',
        status: 'configured',
        releasesAt: null,
      },
    ];
    service.fail.set('POST /api/vault/emergency-access/p9/request', {
      status: 503,
      error: 'recipient_unverified',
    });
    await openEmergency();
    await waitForText('Granted to you');
    clickText('Request access');
    await waitForText(/confirm your email address in estate/i);
  });

  it('prompts for a factor when ARMING is refused, then arms (M15 review)', async () => {
    // `POST /v1/vault/emergency-access` is step-up gated and the redeemed
    // session no longer arrives with one, so this is the path an owner actually
    // takes. Wired late and found by the live drive on the SETUP equivalent.
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    service.fail.set('POST /api/vault/emergency-access', {
      status: 403,
      error: 'stepup_required',
    });
    await openEmergency();
    await waitForText('Ada');
    clickText('Confirm key');
    await waitForText('key confirmed');
    clickText('Arm emergency access');

    await waitForText(/arming emergency access needs a fresh identity check/i);
    service.fail.delete('POST /api/vault/emergency-access');
    submitStepUp();
    await waitForText(/1 contact\(s\) named/i);
    expect(service.calls.some((c) => c.path === '/api/auth/stepup')).toBe(true);
  });

  it('CANCELLING the prompt leaves the arrangement untouched', async () => {
    // Proceeding past a withdrawn consent is the M13 round-3 defect; the
    // ceremony that guards arming must not be the place it comes back.
    const service = installService();
    const armed = {
      id: 'p1',
      granteeContactId: 'c1',
      granteeUserId: GRANTEE,
      waitingPeriodHours: 48,
      status: 'configured',
      requestedAt: null,
      releasesAt: null,
      requestCount: 0,
    };
    service.escrow = { configured: true, threshold: 1, policies: [armed] };
    service.fail.set('DELETE /api/vault/emergency-access/p1', {
      status: 403,
      error: 'stepup_required',
    });
    await openEmergency();
    await waitForText('ready if you cannot');

    clickText('Remove');
    await waitForText(/remove needs a fresh identity check/i);
    clickText('Cancel');
    await waitForText(/needs a fresh identity check, and it was not completed/i);
    expect(service.escrow.policies).toHaveLength(1);
  });
});
