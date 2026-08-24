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
  encryptItem,
  generateRecoveryKeyPair,
  importAesKey,
  publicKeyFingerprint,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { installLifecycle, render } from '../src/client/app';
import { VaultSession } from '../src/client/vault-session';
import { forgetSecretKey } from '../src/client/secret-key-store';

/**
 * THE STATUS VOCABULARY, READ OUT OF THE DDL RATHER THAN RETYPED HERE.
 *
 * The tables below this used to be hand-written rows under a comment saying
 * they were "pinned to `002_emergency_access.sql`" — which is the shape this
 * repo calls a test nobody runs: a claim about the tree asserted in prose. It
 * was also already wrong in the direction that matters. A seventh status would
 * have been covered by the comment and by no assertion, and an UNGATED status
 * is a button offered where the service refuses or, worse, withheld where the
 * service allows — the exact M27 PR3a defect, which is that `released` was
 * collectable nowhere in this client because a hand-list said so.
 *
 * EVERY MIGRATION, NOT JUST THE ONE THAT CREATED THE TABLE, and the PR3a review
 * proved the difference by adding a seventh status that this scan's first draft
 * could not see. Migrations here are APPEND-ONLY and checksummed, so editing
 * `002` raises `MigrationDriftError` — which makes a new file doing
 * `DROP CONSTRAINT … ADD CONSTRAINT … CHECK (status IN (…))` the ONLY legal way
 * to widen the vocabulary, and therefore the only way it will ever actually
 * happen. That is not hypothetical: `003_notification_kinds.sql` in this same
 * directory does exactly that to a constraint `002` declared. A scan anchored
 * on the creating file is blind to every widening that can occur.
 *
 * ANCHORED ON THE TABLE, NOT ON FILE POSITION. Statements are split and only
 * those naming `emergency_access_policies` are read, so a `CHECK (status IN …)`
 * belonging to some other table cannot be mis-attributed here — the failure
 * mode that a slice-to-end-of-file invites. Comments are stripped first: a
 * mention is not a use, and these migrations quote their own vocabularies.
 * LAST definition wins, because append-only means later files supersede.
 *
 * Reading it makes this spec's inputs reach outside its own package, so
 * `apps/vault-web/turbo.json` declares the canonical wide input set. Without
 * that, editing a CHECK constraint would not move this task's hash and the one
 * gate whose input just changed would replay a cached pass
 * (`packages/config/test/turbo-test-inputs.spec.ts` enforces the pairing).
 */
const MIGRATIONS_DIR = join(__dirname, '..', '..', 'services', 'vault', 'migrations');

/** Floor on the corpus itself: a walk that stopped finding files reads as clean. */
const MIN_MIGRATIONS = 6;

function policyStatusDefinitions(): { file: string; values: string[] }[] {
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  if (files.length < MIN_MIGRATIONS) {
    throw new Error(`only ${files.length} migrations found; expected at least ${MIN_MIGRATIONS}`);
  }
  const found: { file: string; values: string[] }[] = [];
  for (const file of files) {
    // EVERY comment goes, not just whole-line ones, and the difference is not
    // cosmetic: statements are split on `;`, and `002` carries a TRAILING
    // comment containing a semicolon (`-- docs/02 §5; opaque here`). Stripping
    // only leading `--` lines left that semicolon in place, which cut the
    // CREATE TABLE in half BEFORE the status CHECK and made this scan return
    // nothing — a parser reporting an empty vocabulary, which without the floor
    // below would have read exactly like a table with nothing to check.
    const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8')
      .split('\n')
      .map((line) => {
        const at = line.indexOf('--');
        return at === -1 ? line : line.slice(0, at);
      })
      .join('\n');
    for (const statement of sql.split(';')) {
      if (!statement.includes('emergency_access_policies')) continue;
      const re = /CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)/gi;
      let m = re.exec(statement);
      while (m !== null) {
        found.push({
          file,
          values: (m[1] as string)
            .split(',')
            .map((v) => v.trim().replace(/^'|'$/g, ''))
            .filter(Boolean),
        });
        m = re.exec(statement);
      }
    }
  }
  return found;
}

const POLICY_STATUS_DEFS = policyStatusDefinitions();

const POLICY_STATUSES: readonly string[] = (() => {
  if (POLICY_STATUS_DEFS.length === 0) {
    throw new Error('no `CHECK (status IN (...))` for emergency_access_policies in any migration');
  }
  // Append-only: the last file to define it is the one in force.
  return POLICY_STATUS_DEFS[POLICY_STATUS_DEFS.length - 1]!.values;
})();

const USER = '11111111-2222-4333-8444-555555555555';
const GRANTEE = '22222222-3333-4444-8555-666666666666';
const PASSWORD = 'a-good-vault-password';

/**
 * BUTTONS THAT MUST NEVER APPEAR ON A GRANTEE'S SURFACE — DERIVED (PR3b review).
 *
 * This was a hand-written list of five, and two of its members could not do
 * anything: `'Delete'` matches no button in the app (the label is `'Delete this
 * item'`, and `toContain` on an array is strict equality), and `'Save changes'`
 * belongs to the owner's edit form, which is not the screen being inspected.
 * A list that cannot match is a list that reports nothing while looking
 * thorough — the shape this repo keeps finding, so this reads the labels out of
 * `app.ts` instead.
 *
 * The CORPUS is every `buttonEl`/`quietButton` label in the client, minus the
 * ones a reader legitimately has. Anything that writes, destroys, navigates
 * into the owner's own vault, or exposes vault-wide settings is therefore
 * forbidden BY DEFAULT: a new owner-side button joins this set the moment it is
 * written, without anybody remembering to add it.
 */
const GRANTEE_ALLOWED_BUTTONS = new Set([
  // The reading surface's own controls, and the ceremony that reaches it.
  'Done',
  'Back',
  'Show',
  'Copy',
  'Open the vault',
  'Open it now',
  'Request access',
  'Confirm key',
  'Let others name me',
  'Emergency access',
  'Cancel',
]);

const OWNER_ONLY_BUTTONS: readonly string[] = (() => {
  const source = readFileSync(join(__dirname, '..', 'src', 'client', 'app.ts'), 'utf8');
  const labels = new Set<string>();
  for (const m of source.matchAll(/(?:buttonEl|quietButton)\(\s*'((?:[^'\\]|\\.)*)'/g)) {
    const label = (m[1] ?? '').replace(/\\'/g, "'");
    if (label && !GRANTEE_ALLOWED_BUTTONS.has(label)) labels.add(label);
  }
  // ANTI-VACUITY: a regex that stopped matching would forbid nothing and every
  // `not.toContain` below would pass. Pin the floor AND a member that must be
  // in it, so a rename cannot empty the set quietly.
  if (labels.size < 10) throw new Error(`derived too few owner buttons: ${labels.size}`);
  if (!labels.has('Add an item')) throw new Error('derivation missed a known owner button');
  return [...labels];
})();

interface Service {
  calls: Array<{ path: string; method: string; body: string }>;
  /** Forced failures, keyed `METHOD /path`. */
  fail: Map<string, { status: number; error: string }>;
  candidates: Array<{ contactId: string; userId: string; name: string }>;
  escrow: {
    configured: boolean;
    threshold: number | null;
    policies: unknown[];
    /** M27 PR3b. `null` is the CLEARED state, mirroring the service. */
    label?: string | null;
  };
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
  /** Held open, so a test can act while a release is in flight. */
  releaseGate: Promise<void> | null;
  /** M27 PR3b: what `GET .../:policyId/items` answers the collected grantee. */
  granteeItems: { status: number; body: unknown } | null;
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
    releaseGate: null,
    granteeItems: null,
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
    // M27 PR3b. Matched by SHAPE rather than by an exact path, because the
    // policy id is generated by the test that armed the escrow.
    if (/\/api\/vault\/emergency-access\/[^/]+\/items(\?|$)/.test(path)) {
      return Promise.resolve(
        state.granteeItems
          ? reply(state.granteeItems.status, state.granteeItems.body)
          : reply(409, { error: 'not_collected' }),
      );
    }
    if (path.endsWith('/release')) {
      // THE DEFAULT REFUSAL IS ONE THE SERVICE CAN STILL SEND. It was 409
      // `already_released` until M27 PR3a made collection repeatable, at which
      // point this fake became the last thing in the repo enforcing a rule the
      // real route had dropped — and the screen test below went on passing
      // against a server that no longer exists. `not_requested` is what a
      // release with no elapsed `releases_at` actually answers.
      const answer = (): unknown =>
        state.release
          ? reply(state.release.status, state.release.body)
          : reply(409, { error: 'not_requested' });
      // A HOLD, so a test can make something happen WHILE the release is in
      // flight. Every real release has a window between the request going out
      // and the key coming back; without a way to open that window here, the
      // only things testable are states that never overlap it.
      return state.releaseGate ? state.releaseGate.then(answer) : Promise.resolve(answer());
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
        label?: string;
        grantees: Array<Record<string, unknown>>;
      };
      state.escrow = {
        configured: true,
        threshold: parsed.threshold,
        // FAITHFUL ABOUT THE ABSENCE, NOT ONLY THE VALUE (M27 PR3b review).
        // This double rebuilt `escrow` without a `label` key at all, so the
        // owner-side write path for the new field had no observer and the
        // review found the bug it was hiding: the form never seeded from the
        // current escrow, so any re-arm cleared the label. `?? null` mirrors
        // the service, which writes `label = EXCLUDED.label` and therefore
        // CLEARS on absence — a double that answered `undefined` here would
        // still be lying about the one arm that matters.
        label: parsed.label ?? null,
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

const GRANTEE_ITEM_ID = '55555555-6666-4777-8888-999999999999';

/**
 * ARM A REAL ESCROW, THE WAY THE OWNER'S DEVICE WOULD (M27 PR3b).
 *
 * The grantee side then reconstructs an ACTUAL key and opens an ACTUAL blob,
 * rather than trusting a fixture to have got the crypto right. The item is
 * sealed with the same `encryptItem` and the same AAD shape the owner's client
 * uses — under the OWNER's id, which is the detail that would break a reader
 * keyed on the caller's own id and would look exactly like a wrong key.
 */
async function armEscrowFor(
  service: Service,
  ownerUserId: string,
  content: Record<string, string> = { title: 'The owner\u2019s secret note' },
): Promise<{
  ownerUserId: string;
  platformPart: string;
  wrappedMasterKeyRecovery: string;
  keyShare: string | undefined;
  threshold: number;
  itemBlob: string;
}> {
  const ownerMasterKey = crypto.getRandomValues(new Uint8Array(32));
  const material = await createEscrow({
    ownerUserId,
    masterKey: ownerMasterKey,
    grantees: [{ granteeUserId: USER, publicKey: fromBase64(service.ownKey?.publicKey ?? '') }],
    threshold: 1,
  });
  const key = await importAesKey(ownerMasterKey, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
  const blob = await encryptItem(
    key,
    { userId: ownerUserId, itemId: GRANTEE_ITEM_ID, blobVersion: 1 },
    new TextEncoder().encode(JSON.stringify(content)),
  );
  return {
    ownerUserId,
    platformPart: material.platformPart,
    wrappedMasterKeyRecovery: material.wrappedMasterKeyRecovery,
    keyShare: material.shares[0]?.sealedShare,
    threshold: material.threshold,
    itemBlob: toBase64(blob),
  };
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

  /*
   * THE LABEL'S WRITE PATH (M27 PR3b review).
   *
   * Three tests rather than one, because the field has three distinct arms and
   * the review found the middle one broken while the outer two would have
   * passed: typing a label must SEND it, re-arming without touching the box
   * must KEEP it, and blanking the box must CLEAR it. Only the second is a
   * behaviour change; it is here with the other two because a seed that
   * defeated the clear would be a worse bug than the one being fixed.
   */
  /**
   * Arm from the emergency screen as it currently stands. Re-arming does NOT
   * re-open the vault: after `configure` the screen re-renders in place with
   * the picker back at "not confirmed", which is exactly the state an owner
   * adding a second contact is in — and the state the seeding defect needed.
   */
  const configures = (service: ReturnType<typeof installService>): readonly { body: string }[] =>
    service.calls.filter((c) => c.method === 'POST' && c.path === '/api/vault/emergency-access');

  const armWith = async (
    service: ReturnType<typeof installService>,
    label?: string,
  ): Promise<void> => {
    /*
     * ANTI-VACUITY, AND THIS HELPER NEEDED IT (M27 PR3b review).
     *
     * Every wait below is satisfiable by the PREVIOUS arm's DOM — "key
     * confirmed" and "1 contact(s) named" are both already on screen when a
     * re-arm starts. The first draft of these tests therefore drove one arm,
     * waited on text that never changed, and asserted against the FIRST
     * request while believing it had made a second. Staging on the picker
     * returning to "not confirmed" is the intermediate assertion that proves
     * the re-render happened, and the request count is the floor that proves
     * the click reached the network.
     */
    await waitForText('Ada');
    await waitForText('not confirmed');
    const before = configures(service).length;
    clickText('Confirm key');
    await waitForText('key confirmed');
    if (label !== undefined) byLabel('What to call this vault').value = label;
    clickText('Arm emergency access');
    await waitForText(/contact\(s\) named/i);
    for (let i = 0; configures(service).length === before && i < 80; i++) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    expect(configures(service).length).toBe(before + 1);
  };

  /** First arm: real enrollment, real SRP unlock, a real published key. */
  const openWithCandidate = async (service: ReturnType<typeof installService>): Promise<void> => {
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    const pair = await generateRecoveryKeyPair();
    service.publishedKeys.set(GRANTEE, toBase64(pair.publicKey));
    await openEmergency();
  };

  const lastConfigureBody = (service: ReturnType<typeof installService>): string =>
    configures(service).at(-1)?.body ?? '';

  it('sends the label the owner typed', async () => {
    const service = installService();
    await openWithCandidate(service);
    await armWith(service, 'The Dehn family vault');

    expect(JSON.parse(lastConfigureBody(service))).toMatchObject({
      label: 'The Dehn family vault',
    });
    await waitForText('They see this vault as “The Dehn family vault”.');
  });

  it('KEEPS the label when the owner re-arms without touching the box', async () => {
    // The defect this closes: `configure` clears the label on absence, so a
    // form that always started blank discarded the name on every re-arm done
    // for some other reason — reverting every grantee to `Vault of <uuid>`,
    // which is the §6yy defect this PR exists to close.
    const service = installService();
    await openWithCandidate(service);
    await armWith(service, 'The Dehn family vault');

    // Re-arm in place, never touching the label field.
    await armWith(service);

    expect(byLabel('What to call this vault').value).toBe('The Dehn family vault');
    expect(JSON.parse(lastConfigureBody(service))).toMatchObject({
      label: 'The Dehn family vault',
    });
    await waitForText('They see this vault as “The Dehn family vault”.');
  });

  it('CLEARS the label when the owner blanks the box', async () => {
    // The other arm, and the reason the seed above must not be a floor: an
    // owner who deletes the name means it, and the omitted field is how this
    // client says so.
    const service = installService();
    await openWithCandidate(service);
    await armWith(service, 'The Dehn family vault');

    await armWith(service, '   ');

    expect(JSON.parse(lastConfigureBody(service))).not.toHaveProperty('label');
    await waitForText('They see your account id.');
  });

  it('names the step a candidate is actually missing, not one it cannot know about', async () => {
    /*
     * FOUND BY DRIVING THE REAL APP (M27 PR3b).
     *
     * The copy said the candidate "has not set up a vault yet" — which the
     * server's 404 does not say, and which was false for the contact the drive
     * used: they HAD a vault and had never published a recovery key. The owner
     * was told to ask for something already done. `granteePublicKey` answers
     * one uniform 404 for both states deliberately, so the only honest copy is
     * one true of both, naming the action that fixes either.
     */
    const service = installService();
    service.candidates = [{ contactId: 'c1', userId: GRANTEE, name: 'Ada' }];
    // No published key for GRANTEE: the route 404s, exactly as it does for a
    // contact with no vault at all. The screen cannot tell them apart.
    await openEmergency();
    await waitForText('Ada');

    clickText('Confirm key');
    await waitForText(/has not published a key yet/i);
    const text = document.body.textContent ?? '';
    // It must not assert the cause the 404 cannot establish…
    expect(text).not.toMatch(/has not set up a vault/i);
    // …and it must name the step that actually fixes it, in both states.
    expect(text).toContain('Let others name me');
    expect(document.body.textContent).not.toContain('key confirmed');
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

    const OWNER_ID = '33333333-4444-4555-8666-777777777777';
    const armed = await armEscrowFor(service, OWNER_ID);
    service.release = { status: 200, body: armed };
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
    /*
     * M27 PR3b MOVED THE ENDING. This waited on the collection's own
     * confirmation — the sentence that said the key had been rebuilt and NOT
     * kept — and PR3b keeps it, in `VaultSession`, so the grantee can read
     * with it. So the proof that reconstruction worked is no longer a message
     * claiming it did: it is the owner's ciphertext OPENING, which is a fact
     * about the key rather than a sentence about it.
     */
    service.granteeItems = {
      status: 200,
      body: {
        items: [
          {
            id: GRANTEE_ITEM_ID,
            itemType: 'secure_note',
            blob: armed.itemBlob,
            blobVersion: 1,
            revision: 1,
            createdAt: '2026-08-01T00:00:00.000Z',
            updatedAt: '2026-08-01T00:00:00.000Z',
          },
        ],
        nextCursor: null,
      },
    };
    await waitForText(/the owner’s secret note/i);
    // And it stays on the device: nothing carries a recovered key back up.
    // THE POINT OF THIS TEST, and it survives PR3b unchanged — the key now
    // lives longer, so the egress question matters more, not less.
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
    /*
     * AND THE SECOND SENTENCE IS NOW THE OTHER WAY ROUND (M27 PR3b).
     *
     * It asserted `not built yet` — the honest limit while reading did not
     * exist. PR3b builds it, so that sentence became false in the same way
     * PR3a's did, and this is the screen where a false sentence does the most
     * damage. UNDERSTATING what the next tap does is the same defect as
     * overstating it: somebody weighing a real emergency has to be told they
     * are about to see the contents.
     */
    expect(warning).toMatch(/shows you what is inside/i);
    expect(warning).not.toMatch(/not built yet/i);

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

  it('reads the status vocabulary from EVERY migration, not just the creating one', () => {
    // The floor and the anti-vacuity, at the level the PR3a review broke. A
    // scan that found no definition, or stopped descending the directory, must
    // not read as "all six covered".
    expect(POLICY_STATUS_DEFS.length).toBeGreaterThan(0);
    expect(POLICY_STATUSES.length).toBeGreaterThan(0);
    // Every definition found must be attributed to a real migration file, and
    // the one in force must be the LAST — comparing the SET, because
    // mis-attribution between two definitions preserves a count.
    const last = POLICY_STATUS_DEFS[POLICY_STATUS_DEFS.length - 1]!;
    expect(last.file).toMatch(/^\d{3}_.*\.sql$/);
    expect([...POLICY_STATUSES].sort()).toEqual([...last.values].sort());
    // POSITIVE CONTROL on the parser: it really is reading the policies table's
    // constraint and not something that merely mentions the words. The set it
    // returns must contain the two statuses this whole PR turns on.
    expect(POLICY_STATUSES).toContain('waiting');
    expect(POLICY_STATUSES).toContain('released');
  });

  it('covers EVERY status in the DDL, in every table', () => {
    // The floor. Any of these tables silently narrowing is how a status stops
    // being considered without anybody noticing, so the corpus is compared as a
    // SET against the CHECK constraint rather than by length.
    const ddl = [...POLICY_STATUSES].sort();
    expect(ddl.length).toBeGreaterThan(0);
    expect(Object.keys(EXPECTATIONS.request).sort()).toEqual(ddl);
    expect(Object.keys(EXPECTATIONS.open).sort()).toEqual(ddl);
    expect(Object.keys(EXPECTATIONS.ownerStops).sort()).toEqual(ddl);
    // The grantee wording table is keyed on the same corpus and asserted in its
    // own test; named here too so this one test states the FULL reach rather
    // than three quarters of it.
    expect(Object.keys(GRANTEE_WORDS).sort()).toEqual(ddl);
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

  /**
   * THE TWO SENTENCES §6yy CALLS THE MOST CONSEQUENTIAL LIE (PR3a review).
   *
   * `app.ts` states in capitals that NEITHER stop may claim the release was
   * undone, and the `ownerStops` table above records only WHETHER a stop
   * exists — it accepts either label by design, because both are stops. So
   * nothing asserted that a released row gets the released-specific wording,
   * and the review proved it with two surviving mutations: forcing the deny
   * ternary to the waiting arm, and the Remove ternary to the generic arm,
   * each producing the pre-PR3a sentence on a post-PR3a status, both green
   * across the whole suite.
   *
   * The waiting side has had this assertion since M15 (`offers one-tap denial
   * on a waiting request` reads back its toast). The released twin, added by
   * this PR, had none — a rule applied to one member of a category.
   */
  const releasedPolicy = {
    id: 'p1',
    granteeContactId: 'c1',
    granteeUserId: GRANTEE,
    waitingPeriodHours: 48,
    status: 'released',
    requestedAt: '2026-08-08T00:00:00.000Z',
    releasesAt: '2026-08-10T00:00:00.000Z',
    releasedAt: '2026-08-10T00:00:00.000Z',
    requestCount: 1,
  };

  it('tells the owner a STOP cannot take back what was already opened', async () => {
    const service = installService();
    service.escrow = { configured: true, threshold: 1, policies: [releasedPolicy] };
    await openEmergency();
    await waitForText(/opened · 48h wait/i);

    clickText('Stop further access');
    await waitForText(/they keep what they already opened/i);
    // The discriminating half: the WAITING sentence must not appear here. It
    // promises the request cannot proceed, which is false about a collection
    // that already completed.
    expect(document.body.textContent).not.toMatch(/that request cannot proceed/i);
    expect(document.body.textContent).toMatch(/nothing further can be handed over/i);
  });

  it('tells the owner REMOVE cannot take back what was already opened', async () => {
    const service = installService();
    service.escrow = { configured: true, threshold: 1, policies: [releasedPolicy] };
    await openEmergency();
    await waitForText(/opened · 48h wait/i);

    clickText('Remove');
    await waitForText(/they keep what they already opened/i);
    // The sentence `app.ts` names as the most consequential lie this screen
    // could tell: it is FALSE about somebody who rebuilt the master key.
    expect(document.body.textContent).not.toMatch(/can no longer open this vault/i);
  });

  /**
   * THE STOP MUST NOT ERASE WHAT IT WAS STOPPING (PR3a review).
   *
   * `deny` writes `denied_by_owner` over `released`, so once the owner acts,
   * `status` no longer records that the master key was handed over. Keyed on
   * the status, this screen told the truth right up until the owner pressed
   * the stop and then reverted to the generic sentence — so an owner who
   * denied and then removed a grantee HOLDING THEIR MASTER KEY was told "that
   * person can no longer open this vault". Those are the two states in this
   * feature whose remedies differ most: one needs a vault reset, the other
   * needs nothing.
   *
   * Both rows below are `denied_by_owner`. The only difference is
   * `releasedAt`, which is why the copy is anchored on it.
   */
  it('still says a collection happened AFTER the owner stops it', async () => {
    const collected = {
      id: 'p1',
      granteeContactId: 'c1',
      granteeUserId: GRANTEE,
      waitingPeriodHours: 48,
      status: 'denied_by_owner',
      requestedAt: '2026-08-08T00:00:00.000Z',
      releasesAt: null,
      releasedAt: '2026-08-10T00:00:00.000Z',
      requestCount: 1,
    };
    const service = installService();
    service.escrow = { configured: true, threshold: 1, policies: [collected] };
    await openEmergency();
    await waitForText(/stopped by you/i);

    // The ROW says it, not only a control the owner might never open.
    expect(document.body.textContent).toMatch(/was opened/i);
    // And Remove must not promise what it cannot deliver.
    clickText('Remove');
    await waitForText(/they keep what they already opened/i);
    expect(document.body.textContent).not.toMatch(/can no longer open this vault/i);
  });

  it('POSITIVE CONTROL: a stop with NO collection keeps the plain sentence', async () => {
    // The discriminating arm. Identical row, `releasedAt: null` — without this
    // the test above passes for a screen that says "was opened" unconditionally.
    const neverCollected = {
      id: 'p1',
      granteeContactId: 'c1',
      granteeUserId: GRANTEE,
      waitingPeriodHours: 48,
      status: 'denied_by_owner',
      requestedAt: '2026-08-08T00:00:00.000Z',
      releasesAt: null,
      releasedAt: null,
      requestCount: 1,
    };
    const service = installService();
    service.escrow = { configured: true, threshold: 1, policies: [neverCollected] };
    await openEmergency();
    await waitForText(/stopped by you/i);
    expect(document.body.textContent).not.toMatch(/was opened/i);
    clickText('Remove');
    await waitForText(/can no longer open this vault/i);
  });

  it('does not invent a collection when the service sends no releasedAt', async () => {
    // A service older than this origin omits the field entirely, and
    // `undefined !== null` is TRUE — which would announce a collection on every
    // row it serves. The predicate falls back to the status instead.
    const legacyRow = {
      id: 'p1',
      granteeContactId: 'c1',
      granteeUserId: GRANTEE,
      waitingPeriodHours: 48,
      status: 'denied_by_owner',
      requestedAt: '2026-08-08T00:00:00.000Z',
      releasesAt: null,
      requestCount: 1,
    };
    const service = installService();
    service.escrow = { configured: true, threshold: 1, policies: [legacyRow] };
    await openEmergency();
    await waitForText(/stopped by you/i);
    expect(document.body.textContent).not.toMatch(/was opened/i);
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

  // ------------------------------------------- M27 PR3b: whose vault is this

  const OWNER_ID = '33333333-4444-4555-8666-777777777777';

  /**
   * docs/03 §6yy's `[OWNER: M27]`, closed. The grantee's row read
   * "Vault of <uuid>" — the SAME defect M27 had already fixed on the owner's
   * side, arriving once more on the other half of one feature, which is
   * exactly what "a rule applied to one member of a category is a rule half
   * applied" describes.
   */
  it('names the owner’s vault by the label the OWNER wrote', async () => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        status: 'configured',
        releasesAt: null,
        releasedAt: null,
        ownerLabel: 'Mum’s vault',
      },
    ];
    await openEmergency();
    await waitForText(/mum’s vault/i);
    // The id is GONE from the row, not merely accompanied by a name.
    expect(document.body.textContent).not.toContain(OWNER_ID);
  });

  /**
   * THE FALLBACK, AND BOTH SPELLINGS OF ABSENT. `ownerLabel` arrives as JSON,
   * so a service older than this origin sends no such field at all — and
   * `undefined !== null` is true, which is how the M12 rule gets broken by a
   * strict-equality check that looks careful. Null and missing must both fall
   * back, and neither may blank the row.
   */
  it.each([
    ['null', null],
    ['missing entirely (an older service)', undefined],
    ['empty (a service that sent a blank)', ''],
  ])('falls back to the owner id when the label is %s', async (_name, label) => {
    const service = installService();
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        status: 'configured',
        releasesAt: null,
        releasedAt: null,
        ...(label === undefined ? {} : { ownerLabel: label }),
      },
    ];
    await openEmergency();
    await waitForText(/ready if they cannot/i);
    expect(document.body.textContent).toContain(`Vault of ${OWNER_ID}`);
  });

  /**
   * THE OWNER SEES WHAT THEY PUBLISHED. An owner who cannot read back the
   * current label cannot tell a blank one from one that failed to save — and
   * this is the one string on this origin whose audience is somebody else, so
   * being wrong about it is being wrong about what another person reads.
   */
  it('echoes the label back to the owner who set it', async () => {
    const service = installService();
    service.escrow = {
      configured: true,
      threshold: 1,
      label: 'The Dehn family vault',
      policies: [],
    };
    await openEmergency();
    await waitForText(/they see this vault as/i);
    expect(document.body.textContent).toContain('The Dehn family vault');
  });

  it('tells an owner with NO label exactly what their grantees see instead', async () => {
    // The discriminating arm: without it the test above passes for a screen
    // that prints whatever it was given and says nothing when given nothing.
    const service = installService();
    service.escrow = { configured: true, threshold: 1, policies: [] };
    await openEmergency();
    await waitForText(/they see your account id/i);
  });

  /**
   * THE READING SURFACE ITSELF — the thing the whole §5.2 ceremony exists to
   * reach, and the screen PR3a could only promise.
   */
  it('opens the owner’s items after a collection, under the owner’s name', async () => {
    const service = installService();
    await openEmergency();
    clickText('Let others name me');
    await waitForText(/your key is published/i);

    // A REAL escrow, built by this test playing the owner's device, so the
    // grantee side reconstructs an actual key rather than trusting a fixture.
    const armed = await armEscrowFor(service, OWNER_ID);
    service.release = { status: 200, body: armed };
    service.granteeItems = {
      status: 200,
      body: {
        items: [
          {
            id: GRANTEE_ITEM_ID,
            itemType: 'secure_note',
            blob: armed.itemBlob,
            blobVersion: 1,
            revision: 1,
            createdAt: '2026-08-01T00:00:00.000Z',
            updatedAt: '2026-08-01T00:00:00.000Z',
          },
        ],
        nextCursor: null,
      },
    };
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
        releasedAt: null,
        ownerLabel: 'Mum’s vault',
      },
    ];

    // Re-enter the screen so it picks up the new granted-to-me state. 'Back'
    // from the recovery-key screen lands on the VAULT, not on emergency
    // access, which is why the round trip is spelled out rather than assumed.
    clickText('Back');
    await waitForText(/nothing here yet/i);
    clickText('Emergency access');
    await waitForText('Your arrangement');
    await waitForText(/ready to open/i);
    clickText('Open the vault');
    await waitForText(/only continue if they genuinely cannot/i);
    clickText('Open it now');

    // THE ITEM'S TITLE, decrypted on this device with a key rebuilt from the
    // escrow. A 200 carrying ciphertext that will not open is the failure this
    // screen could have and a status assertion could not see.
    await waitForText(/the owner’s secret note/i);
    // Under the owner's own name, not their id.
    expect(document.body.textContent).toContain('Mum’s vault');
    expect(document.body.textContent).not.toContain(OWNER_ID);
    // And the owner is told, said on the screen the grantee is looking at.
    expect(document.body.textContent).toMatch(/the owner has been told/i);
  });

  /**
   * THE RUNTIME HALF OF THE READ-ONLY-KEY CLAIM (M27 PR3b review).
   *
   * `fences.spec.ts` checks the `importAesKey` CALL and used to justify
   * stopping there by claiming the key was unreachable from a test. It is not:
   * `collectGrant` returns the `GrantedVault`, so the real key from the real
   * ceremony can be inspected with nothing cut into the module. Spying on the
   * prototype observes the value the app itself received — no production
   * change, and no fixture standing in for the key.
   *
   * WebCrypto enforces `usages`, so this is the layer where "cannot seal a
   * blob into somebody else's Zone A" is a platform guarantee rather than a
   * property of what was built.
   */
  it('the collected key carries no writing usage AT RUNTIME', async () => {
    const collected: CryptoKey[] = [];
    // UNBOUND ON PURPOSE, which is the one case the rule exists to allow: the
    // reference is re-entered as `realCollect.call(this, …)` below, so the
    // instance supplies `this`. Binding it to the prototype — the reflex fix —
    // would hand the real method an object with none of the `#private` fields
    // it reads, and the restore in `finally` would leave a bound method
    // installed for every later test.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const realCollect = VaultSession.prototype.collectGrant;
    VaultSession.prototype.collectGrant = async function (this: VaultSession, input) {
      const real = await realCollect.call(this, input);
      if (real.ok) collected.push(real.data.masterKey);
      return real;
    };
    try {
      const service = installService();
      await readAsGrantee(service);
      // `readAsGrantee` returns on the CLICK, not on the collection — every
      // caller stages on the screen that follows, and so must this one.
      await waitForText(/the owner has been told/i);

      // ANTI-VACUITY: the ceremony really ran and really produced a key, or
      // every assertion below is about an empty array.
      expect(collected).toHaveLength(1);
      const key = collected[0]!;
      // Exactly what reading needs, and nothing that writes.
      expect([...key.usages].sort()).toEqual(['decrypt', 'unwrapKey']);
      for (const forbidden of ['encrypt', 'wrapKey', 'sign', 'deriveKey', 'deriveBits']) {
        expect(key.usages).not.toContain(forbidden);
      }
      // And page script cannot read the owner's master key out of the browser.
      expect(key.extractable).toBe(false);
    } finally {
      VaultSession.prototype.collectGrant = realCollect;
    }
  });

  /**
   * A LOCK LANDING WHILE THE RELEASE IS IN FLIGHT (M27 PR3b review).
   *
   * `collectGrant` checked the session before its awaits and wrote the
   * recovered key after them, unconditionally — so a lock arriving in between
   * was silently undone. The owner's master key ended up installed on a
   * session whose status is `locked`, where `touch()` returns early and
   * therefore never arms another idle timer: the key outlived the control that
   * exists to drop it. §6zz accepted the residual on the premise that the idle
   * lock protects a grantee who walks away, which is this exact case.
   *
   * Driven through `pagehide` because that is a real way to lose the race —
   * shutting the laptop while the release is out — and because it is the one
   * lock trigger a test can fire at an exact moment. The idle timer reaches
   * the same `lock()` by the same path.
   */
  it('does not install the owner’s key when a lock lands mid-collection', async () => {
    const service = installService();
    await openEmergency();
    clickText('Let others name me');
    await waitForText(/your key is published/i);
    const armed = await armEscrowFor(service, OWNER_ID);
    service.release = { status: 200, body: armed };
    service.granteeItems = { status: 200, body: { items: [], nextCursor: null } };
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        granteeUserId: USER,
        waitingPeriodHours: 48,
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
        releasedAt: null,
        ownerLabel: 'Mum’s vault',
      },
    ];

    clickText('Back');
    await waitForText(/nothing here yet/i);
    clickText('Emergency access');
    await waitForText('Your arrangement');
    await waitForText(/ready to open/i);

    // The `pagehide` handler lives in `installLifecycle`, which `mount()` does
    // NOT call — the first draft of this test dispatched the event at nothing,
    // so the lock never fired and it "reproduced" the defect against the fix.
    // Installing it here is what makes the dispatch below mean anything.
    installLifecycle();

    // Hold the release open, start the collection, then lose the device.
    let openTheGate = (): void => {};
    service.releaseGate = new Promise<void>((resolve) => {
      openTheGate = resolve;
    });
    clickText('Open the vault');
    await waitForText(/only continue if they genuinely cannot/i);
    clickText('Open it now');
    // The request is out and waiting on the gate.
    await new Promise((resolve) => setTimeout(resolve, 50));
    window.dispatchEvent(new Event('pagehide'));
    openTheGate();

    // The screen ends up locked, NOT holding somebody else's vault.
    await waitForText('Unlock your vault');
    const text = document.body.textContent ?? '';
    expect(text).not.toContain('Mum’s vault');
    expect(text).not.toMatch(/the owner has been told/i);
    // ANTI-VACUITY: the release really did go out and really did answer, so
    // this is the race and not a collection that never started.
    expect(service.calls.some((c) => c.method === 'POST' && c.path.endsWith('/release'))).toBe(
      true,
    );
  });

  /*
   * EVERY REFUSAL THE READING ROUTE CAN ANSWER (M27 PR3b review).
   *
   * THE CORPUS, stated because a table that does not say what it covers is a
   * table that silently stops covering it: these are the refusals
   * `EmergencyService.readAsGrantee` and the guards above it can produce for a
   * grantee holding a live session — `denied_by_owner` and `not_collected`
   * thrown in `readAsGrantee` itself, `settlement_stage_not_reached` from the
   * settlement gate it runs inside, and the uniform `not_found` from
   * `requireGranteePolicy`. `policy_revoked` is deliberately NOT here: the
   * coverage floor showed that arm was dead, because `markRevoked`
   * soft-deletes and every grantee read filters `deleted_at IS NULL`, so a
   * revoked policy answers as the `not_found` row below.
   * `vault_locked` and 401 are excluded: both are the
   * grantee's OWN session lapsing, they already have correct copy, and neither
   * is a statement about the arrangement.
   *
   * Every one of them used to arrive as `UNKNOWN` -> "Something went wrong.
   * Try again." or as item-shaped copy on a screen holding a whole vault. The
   * three assertions below are the three things that made that wrong, and they
   * are asserted for the whole table rather than per row so a NEW refusal
   * cannot be added with generic copy and stay green.
   */
  const READ_REFUSALS = [
    ['the owner stopped access', 403, 'denied_by_owner', /stopped your access/i],
    ['settlement is holding it', 403, 'settlement_stage_not_reached', /being settled/i],
    ['the arrangement was rebuilt', 409, 'not_collected', /rebuilt since you opened it/i],
    ['the arrangement is gone', 404, 'not_found', /no longer there/i],
  ] as const;

  it.each(READ_REFUSALS)(
    'tells a reading grantee what happened when %s',
    async (_name, status, token, expected) => {
      const service = installService();
      await openEmergency();
      clickText('Let others name me');
      await waitForText(/your key is published/i);
      const armed = await armEscrowFor(service, OWNER_ID);
      service.release = { status: 200, body: armed };
      // The COLLECTION succeeds and the READ is refused, which is the shape
      // every one of these takes in life: the grantee held a release and the
      // arrangement moved under them.
      service.granteeItems = { status, body: { error: token } };
      service.grantedToMe = [
        {
          id: 'p9',
          ownerUserId: OWNER_ID,
          granteeUserId: USER,
          waitingPeriodHours: 48,
          status: 'waiting',
          releasesAt: new Date(Date.now() - 1000).toISOString(),
          releasedAt: null,
          ownerLabel: 'Mum’s vault',
        },
      ];

      clickText('Back');
      await waitForText(/nothing here yet/i);
      clickText('Emergency access');
      await waitForText('Your arrangement');
      await waitForText(/ready to open/i);
      clickText('Open the vault');
      await waitForText(/only continue if they genuinely cannot/i);
      clickText('Open it now');

      await waitForText(expected);
      const text = document.body.textContent ?? '';
      // Not a fault…
      expect(text).not.toContain('Something went wrong');
      // …not advice that cannot succeed…
      expect(text).not.toMatch(/try again/i);
      // …and not a sentence about an item, on a screen holding a vault.
      expect(text).not.toMatch(/that item is no longer there|this item changed/i);
      // The owner's name still heads the screen, so the reader knows WHOSE.
      expect(text).toContain('Mum’s vault');
    },
  );

  /**
   * NOTHING THE GRANTEE PRESSES CAN WRITE. The route serves only
   * `read_by_grantee`, so an edit or a delete would 403 — and a button that
   * 403s reads to the person pressing it as an outage rather than a boundary.
   * Asserted on the RENDERED screen, because "there is no such button" is a
   * property of what was built, not of what the service would refuse.
   */
  it('offers a released grantee no way to change anything', async () => {
    const service = installService();
    await openEmergency();
    clickText('Let others name me');
    await waitForText(/your key is published/i);
    const armed = await armEscrowFor(service, OWNER_ID);
    service.release = { status: 200, body: armed };
    service.granteeItems = {
      status: 200,
      body: {
        items: [
          {
            id: GRANTEE_ITEM_ID,
            itemType: 'secure_note',
            blob: armed.itemBlob,
            blobVersion: 1,
            revision: 1,
            createdAt: '2026-08-01T00:00:00.000Z',
            updatedAt: '2026-08-01T00:00:00.000Z',
          },
        ],
        nextCursor: null,
      },
    };
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
        releasedAt: null,
        ownerLabel: 'Mum’s vault',
      },
    ];
    // Re-enter the screen so it picks up the new granted-to-me state. 'Back'
    // from the recovery-key screen lands on the VAULT, not on emergency
    // access, which is why the round trip is spelled out rather than assumed.
    clickText('Back');
    await waitForText(/nothing here yet/i);
    clickText('Emergency access');
    await waitForText('Your arrangement');
    await waitForText(/ready to open/i);
    clickText('Open the vault');
    await waitForText(/only continue if they genuinely cannot/i);
    clickText('Open it now');
    await waitForText(/the owner’s secret note/i);

    const buttons = [...document.querySelectorAll('button')].map((b) => b.textContent ?? '');
    // ANTI-VACUITY: this really is the reading screen, and it really does have
    // buttons — a screen that failed to render passes every `not.toContain`.
    expect(buttons).toContain('Done');
    for (const forbidden of OWNER_ONLY_BUTTONS) {
      expect(buttons).not.toContain(forbidden);
    }

    /*
     * AND THE ITEM DETAIL SCREEN, WHICH WAS NEVER CHECKED (PR3b review).
     *
     * It is the one that could plausibly drift into reusing the owner's edit
     * form — `renderGrantedItem` exists precisely so it does not — so leaving
     * it unchecked left the list screen guarded and the risky screen open.
     */
    clickText('The owner’s secret note');
    // Stage on the screen actually having CHANGED: the list carries 'Done',
    // the detail carries 'Back'. Waiting on the title would be satisfied by
    // the list, which still shows it.
    for (let i = 0; i < 80 && !findButton('Back'); i++) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const detailButtons = [...document.querySelectorAll('button')].map((b) => b.textContent ?? '');
    expect(detailButtons).not.toContain('Done');
    expect(detailButtons).toContain('Back');
    for (const forbidden of OWNER_ONLY_BUTTONS) {
      expect(detailButtons).not.toContain(forbidden);
    }
  });

  /**
   * A HELPER FOR THE THREE TESTS BELOW, which all need a grantee sitting on the
   * reading screen with a real decrypted item in front of them. Driving the
   * whole ceremony three times inline is three chances to drive it differently.
   */
  async function readAsGrantee(
    service: Service,
    content?: Record<string, string>,
    itemOverrides: Record<string, unknown> = {},
  ): Promise<void> {
    await openEmergency();
    clickText('Let others name me');
    await waitForText(/your key is published/i);
    const armed = await armEscrowFor(service, OWNER_ID, content);
    service.release = { status: 200, body: armed };
    service.granteeItems = {
      status: 200,
      body: {
        items: [
          {
            id: GRANTEE_ITEM_ID,
            itemType: 'secure_note',
            blob: armed.itemBlob,
            blobVersion: 1,
            revision: 1,
            createdAt: '2026-08-01T00:00:00.000Z',
            updatedAt: '2026-08-01T00:00:00.000Z',
            ...itemOverrides,
          },
        ],
        nextCursor: null,
      },
    };
    service.grantedToMe = [
      {
        id: 'p9',
        ownerUserId: OWNER_ID,
        status: 'waiting',
        releasesAt: new Date(Date.now() - 1000).toISOString(),
        releasedAt: null,
        ownerLabel: 'Mum\u2019s vault',
      },
    ];
    clickText('Back');
    await waitForText(/nothing here yet/i);
    clickText('Emergency access');
    await waitForText('Your arrangement');
    await waitForText(/ready to open/i);
    clickText('Open the vault');
    await waitForText(/only continue if they genuinely cannot/i);
    clickText('Open it now');
  }

  /**
   * THE DETAIL SCREEN, AND THE SECRET IT HIDES BY DEFAULT.
   *
   * A grantee reading somebody else's vault is, by construction, reading it
   * somewhere unusual — a hospital corridor, a solicitor's office — so the
   * secret starts masked for the same reason the owner's own form does, and
   * nothing about being a grantee relaxes that.
   */
  it('opens one of the owner’s items, masked until revealed', async () => {
    const service = installService();
    await readAsGrantee(service, {
      title: 'Bank login',
      username: 'jane@example.com',
      url: 'https://bank.example',
      notes: 'the joint account',
      secret: 'hunter2-the-real-one',
    });
    await waitForText(/bank login/i);
    clickText('Bank login');
    await waitForText(/jane@example.com/i);

    // Masked by default — the secret is NOT in the document before Show.
    expect(document.body.textContent).not.toContain('hunter2-the-real-one');
    expect(document.body.textContent).toContain('••••••••');
    // The other decrypted fields ARE there, which is what makes the absence
    // above a statement about the SECRET rather than about a blank screen.
    expect(document.body.textContent).toContain('https://bank.example');
    expect(document.body.textContent).toContain('the joint account');

    clickText('Show');
    expect(document.body.textContent).toContain('hunter2-the-real-one');
    clickText('Show');
    expect(document.body.textContent).not.toContain('hunter2-the-real-one');
  });

  it('tells a grantee the same clipboard story the owner is told', async () => {
    const service = installService();
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });
    await readAsGrantee(service, { title: 'Bank login', secret: 'hunter2-the-real-one' });
    await waitForText(/bank login/i);
    clickText('Bank login');
    await waitForText(/••••••••/);
    clickText('Copy');
    // ONE BEHAVIOUR, ONE SPELLING: the grantee's clipboard clears on the same
    // timer as the owner's, so it must not be described differently.
    await waitForText(/your clipboard clears in 20 seconds/i);
    expect(writeText).toHaveBeenCalledWith('hunter2-the-real-one');
  });

  /**
   * AN UNREADABLE ITEM IS SHOWN, NOT HIDDEN, and does not say WHY.
   *
   * `#openBlob` refuses to distinguish a wrong key from a malformed blob — one
   * message, so the pair is never an oracle — and a grantee must still be able
   * to see that something is there. The blob here is served at a blobVersion
   * the ciphertext was not sealed against, which is the anti-rollback binding
   * refusing exactly as designed.
   */
  it('shows an item it could not open, without saying which half failed', async () => {
    const service = installService();
    await readAsGrantee(service, { title: 'Bank login', secret: 's' }, { blobVersion: 9 });
    await waitForText(/could not be read/i);
    clickText('(this item could not be read)');
    await waitForText(/this item could not be read/i);
    const text = document.body.textContent ?? '';
    // Never an oracle: no wording that separates a wrong key from a bad blob.
    expect(text).not.toMatch(/wrong key|bad key|malformed|corrupt|decryption failed/i);
    // ANTI-VACUITY: this really is the detail screen for that item.
    expect(text).toContain('Secure note');
  });

  it('drops the collected escrow when the grantee presses Done', async () => {
    const service = installService();
    await readAsGrantee(service);
    await waitForText(/the owner’s secret note/i);
    const reads = service.calls.filter((c) => c.path.includes('/items')).length;
    clickText('Done');
    await waitForText('Your arrangement');
    // The escrow is gone: re-entering the reading screen is no longer possible
    // without collecting again, so nothing further is fetched.
    expect(service.calls.filter((c) => c.path.includes('/items')).length).toBe(reads);
    // And the grantee's OWN vault is untouched — Done is not a lock.
    clickText('Back');
    await waitForText(/nothing here yet/i);
  });
});
