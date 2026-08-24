/**
 * @jest-environment jsdom
 */

/**
 * THE OWNER'S RESTORE SURFACE (M27 PR2).
 *
 * Its own file, on the `screens-stepup.spec.ts` precedent: a real enrollment is
 * a 650k-iteration PBKDF2 plus an SRP exchange, so every screens suite pays for
 * one and they are split to keep any single one runnable.
 *
 * WHAT THIS SUITE HAS TO BE FAITHFUL ABOUT, because the shipped doubles are not.
 * The existing screens doubles answer DELETE with a bare 204 and drop the row,
 * so nothing they hold could ever appear on a restorable list. This one keeps a
 * RETIRED map and a per-item version log, and it branches the four restore
 * paths BEFORE the generic `/api/vault/items` arms — a `POST …/undelete` that
 * fell into the item-CREATE arm would `JSON.parse('')` and reject the transport,
 * surfacing as an invented NETWORK failure rather than a wrong shape.
 *
 * TWO NUMBERS THAT MUST NEVER AGREE. `revision` and `blobVersion` advance
 * independently here, exactly as the service's trigger and its writer do. A
 * fixture where they coincide cannot catch a caller that sends one where the
 * other belongs, which is the defect M27 PR1a existed to make impossible and
 * PR1b's own review found again in three fixtures.
 *
 * AND NO IMAGE CARRIES THE LIVE REVISION. The capture trigger reads OLD, so an
 * image always holds the revision the row had BEFORE the write that captured
 * it. That is asserted here as an invariant rather than assumed, because the
 * screen's "every version is offered" rule depends on it.
 */
import 'fake-indexeddb/auto';
import {
  createServerEphemeral,
  decodeGroupElement,
  encodeGroupElement,
  fromBase64,
  toBase64,
  verifyClientSession,
} from '@estate/vault-crypto';
import { render } from '../src/client/app';
import { forgetSecretKey } from '../src/client/secret-key-store';

const USER = '11111111-2222-4333-8444-555555555555';
const PASSWORD = 'a-good-vault-password';

interface Row {
  id: string;
  itemType: string;
  blob: string;
  blobVersion: number;
  revision: number;
  createdAt: string;
  updatedAt: string;
}
interface Image {
  revision: number;
  itemType: string;
  blob: string;
  blobVersion: number;
  versionedAt: string;
}
interface Service {
  calls: Array<{ path: string; method: string; body: string; headers: Record<string, string> }>;
  items: Map<string, Row>;
  retired: Map<string, Row>;
  versions: Map<string, Image[]>;
  fail: Map<string, { status: number; error: string }>;
}

function installService(): Service {
  const state: Service = {
    calls: [],
    items: new Map(),
    retired: new Map(),
    versions: new Map(),
    fail: new Map(),
  };
  let keyset: Record<string, string> | null = null;
  let ephemeral: Awaited<ReturnType<typeof createServerEphemeral>> | null = null;

  const reply = (status: number, payload: unknown): unknown => ({
    ok: status >= 200 && status < 300,
    status,
    text: () => Promise.resolve(JSON.stringify(payload)),
  });

  /** Capture OLD, exactly as `vault_items_capture_version` does. */
  const capture = (row: Row): void => {
    const log = state.versions.get(row.id) ?? [];
    log.push({
      revision: row.revision,
      itemType: row.itemType,
      blob: row.blob,
      blobVersion: row.blobVersion,
      versionedAt: `2026-08-2${(log.length % 9) + 1}T10:0${log.length % 9}:00.000Z`,
    });
    state.versions.set(row.id, log);
  };

  globalThis.fetch = ((path: string, init: RequestInit = {}) => {
    const method = init.method ?? 'GET';
    const body = typeof init.body === 'string' ? init.body : '';
    const headers = (init.headers ?? {}) as Record<string, string>;
    state.calls.push({ path, method, body, headers });

    const bare = path.split('?')[0] as string;
    const forced = state.fail.get(`${method} ${bare}`);
    if (forced) return Promise.resolve(reply(forced.status, { error: forced.error }));

    if (path === '/api/auth/session') {
      return Promise.resolve(reply(200, { userId: USER, audience: 'vault' }));
    }
    if (path === '/api/auth/logout') return Promise.resolve(reply(200, { status: 'ok' }));
    if (path === '/api/vault/keyset' && method === 'GET') {
      return Promise.resolve(reply(200, { enrolled: keyset !== null, updatedAt: null }));
    }
    if (path === '/api/vault/keyset' && method === 'POST') {
      keyset = JSON.parse(body) as Record<string, string>;
      return Promise.resolve(reply(201, { enrolled: true, updatedAt: null }));
    }
    if (path === '/api/vault/lock') return Promise.resolve(reply(204, null));
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

    // ---- THE RESTORE ROUTES, BEFORE THE GENERIC ITEM ARMS ----
    if (bare === '/api/vault/items/restorable' && method === 'GET') {
      return Promise.resolve(reply(200, { items: [...state.retired.values()], nextCursor: null }));
    }
    const versionsMatch = /^\/api\/vault\/items\/([^/]+)\/versions$/.exec(bare);
    if (versionsMatch && method === 'GET') {
      const id = versionsMatch[1] as string;
      const cursor = new URL(path, 'http://x').searchParams.get('cursor');
      // Newest first, cursor EXCLUSIVE — the service's own semantics.
      const all = [...(state.versions.get(id) ?? [])].sort((a, b) => b.revision - a.revision);
      const after = cursor === null ? all : all.filter((v) => v.revision < Number(cursor));
      const page = after.slice(0, 2);
      const more = after.length > page.length;
      return Promise.resolve(
        reply(200, {
          versions: page,
          nextCursor: more ? String(page[page.length - 1]?.revision) : null,
        }),
      );
    }
    const undeleteMatch = /^\/api\/vault\/items\/([^/]+)\/undelete$/.exec(bare);
    if (undeleteMatch && method === 'POST') {
      const id = undeleteMatch[1] as string;
      const row = state.retired.get(id);
      if (!row) return Promise.resolve(reply(404, { error: 'not_found' }));
      capture(row);
      const back = { ...row, revision: row.revision + 1 };
      state.retired.delete(id);
      state.items.set(id, back);
      return Promise.resolve(reply(200, back));
    }
    const restoreMatch = /^\/api\/vault\/items\/([^/]+)\/restore$/.exec(bare);
    if (restoreMatch && method === 'POST') {
      const id = restoreMatch[1] as string;
      const row = state.items.get(id);
      if (!row) return Promise.resolve(reply(404, { error: 'not_found' }));
      const wanted = (JSON.parse(body) as { revision: number }).revision;
      if (headers['if-match'] !== String(row.revision)) {
        return Promise.resolve(reply(409, { error: 'version_conflict' }));
      }
      const image = (state.versions.get(id) ?? []).find((v) => v.revision === wanted);
      if (!image) return Promise.resolve(reply(404, { error: 'version_not_found' }));
      capture(row);
      const restored = {
        ...row,
        itemType: image.itemType,
        blob: image.blob,
        blobVersion: image.blobVersion,
        revision: row.revision + 1,
      };
      state.items.set(id, restored);
      return Promise.resolve(reply(200, restored));
    }

    // ---- the generic item arms ----
    if (path.startsWith('/api/vault/items') && method === 'POST') {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      const row = {
        ...(parsed as unknown as Row),
        blobVersion: 1,
        revision: 41,
        createdAt: 'now',
        updatedAt: '2026-08-08',
      };
      state.items.set(row.id, row);
      return Promise.resolve(reply(201, row));
    }
    if (path.startsWith('/api/vault/items') && method === 'PUT') {
      const id = bare.split('/').pop() as string;
      const existing = state.items.get(id) as Row;
      capture(existing);
      const parsed = JSON.parse(body) as Record<string, unknown>;
      const row: Row = {
        ...existing,
        ...parsed,
        id,
        // Independently: the writer chooses one, the trigger the other.
        blobVersion: existing.blobVersion + 1,
        revision: existing.revision + 1,
        updatedAt: '2026-08-09',
      };
      state.items.set(id, row);
      return Promise.resolve(reply(200, row));
    }
    if (path.startsWith('/api/vault/items') && method === 'GET') {
      return Promise.resolve(reply(200, { items: [...state.items.values()], nextCursor: null }));
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
const clickText = (text: string): void => {
  const button = [...document.querySelectorAll('button')].find((b) =>
    b.textContent?.includes(text),
  );
  if (!button) throw new Error(`no button "${text}". Saw: ${document.body.textContent}`);
  button.click();
};
const submitForm = (index = 0): void => {
  const forms = document.querySelectorAll('form');
  forms[index]?.dispatchEvent(new Event('submit', { cancelable: true }));
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
const bodyText = (): string => document.body.textContent ?? '';
const waitForRows = async (count: number, deadlineMs = 30_000): Promise<void> => {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    const rows = document.querySelectorAll('ul.items li').length;
    if (rows === count) return;
    if (Date.now() > deadline) {
      throw new Error(
        `timed out waiting for ${count} rows; saw ${rows}. ${bodyText().slice(0, 400)}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

async function openVaultWithItem(title = 'Bank — joint'): Promise<void> {
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
  clickText('Add an item');
  await waitForText('Add an item');
  byLabel('Title').value = title;
  byLabel('Password or secret').value = 'the-original-secret';
  submitForm();
  await waitForText(title);
}

describe('the restore surface (M27 PR2)', () => {
  jest.setTimeout(180_000);
  let service: Service;

  beforeEach(() => {
    service = installService();
    mount();
  });
  afterEach(async () => {
    await forgetSecretKey(USER);
  });

  describe('deleted items', () => {
    it('says nothing is waiting — and that is NOT the failed-load sentence', async () => {
      await openVaultWithItem();
      clickText('Deleted items');
      await waitForText('Nothing you have deleted');
      // A refused read and an empty vault are different facts. Asserting the
      // wrong sentence is ABSENT is the half that catches a collapse.
      expect(bodyText()).not.toContain('could not load your deleted items');
    });

    it('renders a REFUSED load as a failure, never as an empty list', async () => {
      await openVaultWithItem();
      service.fail.set('GET /api/vault/items/restorable', {
        status: 503,
        error: 'upstream_unavailable',
      });
      clickText('Deleted items');
      await waitForText('could not load your deleted items');
      expect(bodyText()).not.toContain('Nothing you have deleted');
    });

    it('brings a retired item back and says so exactly once', async () => {
      await openVaultWithItem();
      // Seeded rather than driven through DELETE: that route is the one item
      // route behind a step-up, and driving it here would make this suite's
      // "no step-up on the restore surface" assertion fail for an unrelated
      // reason. What is under test is the restore surface, not the delete.
      const live = [...service.items.values()][0] as Row;
      service.items.delete(live.id);
      service.retired.set(live.id, live);

      clickText('Deleted items');
      await waitForText('Bring it back');
      expect(bodyText()).toContain('Bank — joint');

      clickText('Bring it back');
      await waitForText('is back in your vault');
      expect(service.items.has(live.id)).toBe(true);
      expect(service.retired.has(live.id)).toBe(false);
    });

    /**
     * THE RACE ARM, and this test says so because the steady state cannot reach
     * it. `REASON_DISPOSITION` classes `vault_reset` as unrestorable, so
     * `RESTORABLE_REASONS` is `['user_delete']` and a reset-killed row is on NO
     * screen — not the vault list, not this one. `item_unrestorable` arrives
     * only when a reset lands BETWEEN the list read and the undelete: the row
     * was listed while it still said `user_delete`. That is the sequence forced
     * here, and it is why the client must handle a token its own list can never
     * produce.
     */
    it('says a reset-killed item can NEVER come back, and does not say "try again"', async () => {
      await openVaultWithItem();
      const live = [...service.items.values()][0] as Row;
      service.items.delete(live.id);
      service.retired.set(live.id, live);
      clickText('Deleted items');
      await waitForText('Bring it back');

      service.fail.set(`POST /api/vault/items/${live.id}/undelete`, {
        status: 409,
        error: 'item_unrestorable',
      });
      clickText('Bring it back');
      await waitForText('cannot be brought back');
      // The remedy that can never work must be ABSENT.
      expect(bodyText()).not.toContain('Reload and try again');
      expect(bodyText()).not.toContain('looking at its history');
    });

    /**
     * THE WAY OUT IS THE LIST, NEVER THE ITEM.
     *
     * `renderVault` re-reads, so returning here also refreshes what the reader
     * just changed. Landing them back on an item form instead would hand them
     * a PRE-restore `OpenedItem`, and the next save would seal against a
     * `blobVersion` the row no longer has — the one path that bricks a row.
     */
    it('returns to the vault LIST, with a re-read behind it', async () => {
      await openVaultWithItem('Bank — joint');
      const before = service.calls.filter((c) => c.method === 'GET' && c.path.includes('items?'));
      clickText('Deleted items');
      await waitForText('Nothing you have deleted');
      clickText('Back');
      await waitForText('Locks after');
      expect(bodyText()).toContain('Bank — joint');
      // A re-read, not a cached repaint.
      const after = service.calls.filter((c) => c.method === 'GET' && c.path.includes('items?'));
      expect(after.length).toBeGreaterThan(before.length);
      // And NOT the edit form: no secret field is on screen.
      expect(bodyText()).not.toContain('Password or secret');
    });
  });

  describe('history', () => {
    /**
     * THE CAPTURE TIME IS THE INSTANT, NOT THE STRING THE SERVER SPELLED.
     *
     * FOUND BY DRIVING THE REAL APP. The first implementation trimmed the ISO
     * text, so an item edited at 17:00 on a Sunday in Phoenix showed a capture
     * time of Monday 00:00 — a wrong DATE, on the one screen whose whole job is
     * saying when something changed.
     *
     * ASSERTED AS AN EQUIVALENCE RATHER THAN AN EXPECTED STRING, and that is
     * the load-bearing choice. Any assertion naming a literal like
     * `2026-08-23 17:00` states a fact about the RUNNER's zone, and CI runs in
     * UTC — where the trim that caused this defect and the fix are
     * indistinguishable. Two spellings of the SAME INSTANT must render
     * identically, which is false for the trim in every zone including UTC.
     */
    it('renders an instant, not its spelling — the same moment two ways reads the same', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');

      const live = [...service.items.values()][0] as Row;
      const log = service.versions.get(live.id) as Image[];
      const image = log[0] as Image;

      // Z spelling first.
      image.versionedAt = '2026-08-24T00:00:31.000Z';
      clickText('History');
      await waitForText('Put this version back');
      const asZulu = document.querySelector('ul.items li .item-type')?.textContent ?? '';

      // The identical instant, written with an offset instead.
      image.versionedAt = '2026-08-23T17:00:31.000-07:00';
      expect(Date.parse(image.versionedAt)).toBe(Date.parse('2026-08-24T00:00:31.000Z'));
      clickText('Back');
      await waitForText('Locks after');
      clickText('History');
      await waitForText('Put this version back');
      const asOffset = document.querySelector('ul.items li .item-type')?.textContent ?? '';

      // ANTI-VACUITY: the row actually carries a rendered time, so two empty
      // strings cannot agree their way to a pass.
      expect(asZulu).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
      expect(asOffset).toBe(asZulu);
      // AND NOTHING MORE. A line asserting the rendering is NOT '2026-08-24
      // 00:00' was here and it was itself the mistake these comments warn
      // about: under TZ=UTC that IS the correct local rendering, so the
      // assertion failed on CI while passing in Phoenix. It was found by this
      // PR's own review after I proved the MUTATION red under TZ=UTC and never
      // ran the fix green in the same zone — the positive control CLAUDE.md
      // asks for, skipped in exactly the arm that mattered. The equivalence
      // above already discriminates: the trim renders the two spellings
      // differently in EVERY zone, UTC included.
    });

    /**
     * TWO IMAGES FROM THE SAME MINUTE ARE TWO DIFFERENT ROWS (M27 PR5).
     *
     * FOUND BY DRIVING, and this is the assertion that was missing rather than
     * the one that was wrong. The test above pins that one instant renders the
     * same however it is SPELLED. Nothing pinned the converse — that two
     * DIFFERENT instants render differently — so a formatter that threw away
     * precision satisfied every existing assertion here. Minute resolution did,
     * and the drive hit it on the first try: editing an item and then putting
     * the previous version back captures the replaced image, 26 seconds after
     * the first, and the History screen showed two rows identical to the
     * character, each offering "Put this version back", holding different
     * secrets.
     *
     * The gap is a general one worth naming: an equivalence assertion is only
     * half a specification. `x renders like y` is satisfied by a function that
     * renders EVERYTHING alike, and the anti-vacuity floor beside it — a regex
     * that the output is shaped like a date — is satisfied by that function too.
     * A discrimination assertion is what closes it.
     */
    it('tells two versions from the same minute apart — precision is the whole job here', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');

      const live = [...service.items.values()][0] as Row;
      const log = service.versions.get(live.id) as Image[];
      const image = log[0] as Image;

      // The two instants the drive actually produced: an edit, then the restore
      // that replaced it, inside one minute.
      image.versionedAt = '2026-08-24T22:05:22.000Z';
      clickText('History');
      await waitForText('Put this version back');
      const first = document.querySelector('ul.items li .item-type')?.textContent ?? '';

      image.versionedAt = '2026-08-24T22:05:48.000Z';
      clickText('Back');
      await waitForText('Locks after');
      clickText('History');
      await waitForText('Put this version back');
      const second = document.querySelector('ul.items li .item-type')?.textContent ?? '';

      // ANTI-VACUITY BEFORE THE DISCRIMINATION: two empty strings differ from
      // nothing, and a row that stopped rendering a time would read as a pass
      // on `not.toBe` alone.
      expect(first).toMatch(/\d{2}:\d{2}:\d{2}$/);
      expect(second).toMatch(/\d{2}:\d{2}:\d{2}$/);
      expect(second).not.toBe(first);

      // AND THE SAME MINUTE, so this cannot pass by the fixture drifting into
      // two different minutes — which would leave the defect uncovered while
      // the test went green.
      expect(first.slice(0, -3)).toBe(second.slice(0, -3));
    });

    /**
     * A TIME THAT WILL NOT PARSE LEAVES NO WRECKAGE ON SCREEN.
     *
     * `apps/web/src/lib/datetime.ts`'s rule, applied on this origin: a failure
     * to display a time must not look like a fault in the owner's own vault.
     * "Invalid Date" does, and so does a row that trails off after "Password ·".
     */
    it('shows no time rather than "Invalid Date", and drops the separator with it', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');

      const live = [...service.items.values()][0] as Row;
      const log = service.versions.get(live.id) as Image[];
      (log[0] as Image).versionedAt = 'not a time at all';

      clickText('History');
      await waitForText('Put this version back');
      const row = document.querySelector('ul.items li .item-type')?.textContent ?? '';
      expect(row).not.toContain('Invalid Date');
      expect(row).toBe('Password');
      expect(bodyText()).not.toContain('NaN');

      // The restore notice loses the clause rather than the sentence.
      clickText('Put this version back');
      await waitForText('Put back the version');
      expect(bodyText()).toContain('The version you replaced is still in this history');
      expect(bodyText()).not.toContain('version from .');
    });

    it('says an unedited item has no history — not an error, not a 404', async () => {
      await openVaultWithItem();
      clickText('History');
      await waitForText('has not been changed since you created it');
      expect(bodyText()).not.toContain("could not load this item's history");
    });

    it('offers every captured version, and no image carries the live revision', async () => {
      await openVaultWithItem('Bank — joint');
      // Two real edits through the UI, so the images are ones a client made.
      for (const secret of ['second-secret', 'third-secret']) {
        clickText('Bank — joint');
        await waitForText('Password or secret');
        byLabel('Password or secret').value = secret;
        submitForm();
        await waitForText('Bank — joint');
      }
      const live = [...service.items.values()][0] as Row;
      const images = service.versions.get(live.id) ?? [];
      expect(images.length).toBeGreaterThanOrEqual(2);
      // THE INVARIANT THE SCREEN'S RULE RESTS ON. The capture trigger reads
      // OLD, so the live revision is never among the images — which is why
      // every row may be offered and no "current" row has to be filtered out.
      expect(Math.max(...images.map((i) => i.revision))).toBeLessThan(live.revision);
      // And the two counters genuinely disagree, or the assertions below could
      // not tell one from the other.
      expect(images.some((i) => i.revision !== i.blobVersion)).toBe(true);

      clickText('History');
      await waitForText('Put this version back');
      const offered = [...document.querySelectorAll('button')].filter((b) =>
        b.textContent?.includes('Put this version back'),
      );
      const shown = document.querySelectorAll('ul.items li').length;
      expect(offered).toHaveLength(shown);
    });

    it('sends the LIVE revision as If-Match and the IMAGE revision as the body', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');

      const live = [...service.items.values()][0] as Row;
      const image = (service.versions.get(live.id) ?? [])[0] as Image;
      // The arm where the two DISAGREE is the only one that can catch a swap.
      expect(image.revision).not.toBe(live.revision);
      expect(image.blobVersion).not.toBe(live.revision);

      clickText('History');
      await waitForText('Put this version back');
      clickText('Put this version back');
      await waitForText('Put back the version from');

      const call = service.calls.filter((c) => c.path.endsWith('/restore')).at(-1);
      expect(call?.headers['if-match']).toBe(String(live.revision));
      expect(JSON.parse(call?.body ?? '{}')).toEqual({ revision: image.revision });
      // blobVersion appears in NEITHER slot.
      expect(call?.headers['if-match']).not.toBe(String(live.blobVersion));
    });

    it('separates a stale token from a version that is gone', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');
      const live = [...service.items.values()][0] as Row;

      clickText('History');
      await waitForText('Put this version back');
      service.fail.set(`POST /api/vault/items/${live.id}/restore`, {
        status: 404,
        error: 'version_not_found',
      });
      clickText('Put this version back');
      await waitForText('That version is no longer available');
      // The ITEM is plainly on screen, so the item-level sentence would be false.
      expect(bodyText()).not.toContain('That item is no longer there');

      service.fail.set(`POST /api/vault/items/${live.id}/restore`, {
        status: 409,
        error: 'version_conflict',
      });
      clickText('Put this version back');
      await waitForText('This changed since you opened it');
      // SURFACE-NEUTRAL on purpose: `version_conflict` is thrown by the item
      // EDIT save too, so a sentence naming this screen would be false there.
      expect(bodyText()).not.toContain('history and try again');
      // …and the refusal that can never be retried must not appear here.
      expect(bodyText()).not.toContain('cannot be brought back');
    });

    /**
     * PAGINATION, AND THE CURSOR THAT IS NEVER REBUILT.
     *
     * The double pages at 2 to keep the fixture small; the service's real page
     * is 50. What is being proved is not the number but the SHAPE: the first
     * read carries no cursor, the second carries back EXACTLY the string the
     * server handed out, and the second page is APPENDED to the first rather
     * than replacing it. A screen that replaced would silently lose the newest
     * versions the moment an item had more history than one page.
     */
    it('appends the next page and hands the cursor back verbatim', async () => {
      await openVaultWithItem('Bank — joint');
      for (const secret of ['second-secret', 'third-secret', 'fourth-secret']) {
        clickText('Bank — joint');
        await waitForText('Password or secret');
        byLabel('Password or secret').value = secret;
        submitForm();
        await waitForText('Bank — joint');
      }
      const live = [...service.items.values()][0] as Row;
      const images = service.versions.get(live.id) ?? [];
      // ANTI-VACUITY: there must be MORE history than one page holds, or a
      // screen that never paged at all would pass this test unchanged.
      expect(images.length).toBeGreaterThan(2);

      clickText('History');
      await waitForText('Put this version back');
      const firstPage = document.querySelectorAll('ul.items li').length;
      expect(firstPage).toBe(2);
      expect(firstPage).toBeLessThan(images.length);

      const opening = service.calls.filter((c) => c.path.includes('/versions')).at(-1);
      expect(opening?.path).not.toContain('cursor=');

      clickText('Show older');
      // Staged on the DOM the second read produces, not on a sentence the
      // FIRST page already put there — one `waitForText` across a re-render
      // that changes nothing visible returns instantly and proves nothing.
      await waitForRows(images.length);
      const versionCalls = service.calls.filter((c) => c.path.includes('/versions'));
      expect(versionCalls).toHaveLength(2);

      // The cursor the client sent is the one the server minted — not derived
      // from a row, not re-serialised, not off by one.
      const oldestOnFirstPage = [...images].sort((a, b) => b.revision - a.revision)[1] as Image;
      const sent = new URL(versionCalls[1]?.path ?? '', 'http://x').searchParams.get('cursor');
      expect(sent).toBe(String(oldestOnFirstPage.revision));

      // APPENDED, not replaced: every image is now on screen and the exhausted
      // list stops offering more.
      expect(document.querySelectorAll('ul.items li')).toHaveLength(images.length);
      expect(bodyText()).not.toContain('Show older');
    });

    /**
     * A HISTORY THAT COULD NOT BE READ IS NOT A HISTORY THAT IS EMPTY.
     *
     * The same rule the deleted-items list follows: two facts with different
     * remedies must never share a sentence. Reload fixes one of these and
     * nothing about the item fixes the other.
     */
    it('renders a REFUSED history as a failure, never as "never been changed"', async () => {
      await openVaultWithItem('Bank — joint');
      const live = [...service.items.values()][0] as Row;
      service.fail.set(`GET /api/vault/items/${live.id}/versions`, {
        status: 503,
        error: 'unavailable',
      });
      clickText('History');
      await waitForText("could not load this item's history");
      expect(bodyText()).toContain('temporarily unreachable');
      expect(bodyText()).not.toContain('has not been changed since you created it');
      // …and the reader is not stranded on it.
      clickText('Back');
      await waitForText('Locks after');
      expect(bodyText()).toContain('Bank — joint');
    });
  });

  describe('a blob this client cannot open', () => {
    it('shows the version but WITHHOLDS the restore control', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');

      const live = [...service.items.values()][0] as Row;
      const log = service.versions.get(live.id) as Image[];
      // Corrupt the captured ciphertext: the AEAD refuses it exactly as it
      // would refuse a blob belonging to another key or another version.
      (log[0] as Image).blob = toBase64(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));

      clickText('History');
      await waitForText('could not be read');
      // BOTH halves. The row is present — an owner must be able to see the
      // past exists — and the button that would write it over live content is
      // gone. Restoring a blob nobody can open is the one action on this
      // screen that destroys something.
      expect(document.querySelectorAll('ul.items li')).toHaveLength(log.length);
      expect(
        [...document.querySelectorAll('button')].filter((b) =>
          b.textContent?.includes('Put this version back'),
        ),
      ).toHaveLength(log.length - 1);
    });

    it('KEEPS "Bring it back" on an unreadable deleted item — undelete writes no ciphertext', async () => {
      await openVaultWithItem();
      const live = [...service.items.values()][0] as Row;
      service.items.delete(live.id);
      service.retired.set(live.id, {
        ...live,
        blob: toBase64(new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9])),
      });

      clickText('Deleted items');
      await waitForText('could not be read');
      // The deliberate OPPOSITE of the version case above: undelete clears
      // `deleted_at` and writes no content, so offering it here is honest —
      // the item comes back exactly as unreadable as it already was.
      expect(
        [...document.querySelectorAll('button')].filter((b) =>
          b.textContent?.includes('Bring it back'),
        ),
      ).toHaveLength(1);
    });
  });

  describe('what the surface never does', () => {
    it('reads no history and no restorable list until asked', async () => {
      await openVaultWithItem();
      clickText('Bank — joint');
      await waitForText('Password or secret');
      // Each of those reads is an audited ciphertext disclosure — one user
      // action, one call, is a security property rather than a perf note.
      expect(
        service.calls.filter((c) => c.path.includes('/versions') || c.path.includes('/restorable')),
      ).toEqual([]);
    });

    it('never asks for a step-up on the restore surface', async () => {
      await openVaultWithItem();
      const live = [...service.items.values()][0] as Row;
      service.items.delete(live.id);
      service.retired.set(live.id, live);
      const before = service.calls.length;
      clickText('Deleted items');
      await waitForText('Bring it back');
      clickText('Bring it back');
      await waitForText('is back in your vault');
      // None of the four routes carries StepUpGuard, deliberately. Inventing
      // ceremony here is the same inversion as adding the guard.
      expect(service.calls.slice(before).filter((c) => c.path.includes('stepup'))).toEqual([]);
    });

    it('addresses exactly the four routes it is the consumer for', async () => {
      await openVaultWithItem('Bank — joint');
      clickText('Bank — joint');
      await waitForText('Password or secret');
      byLabel('Password or secret').value = 'second-secret';
      submitForm();
      await waitForText('Bank — joint');
      const live = [...service.items.values()][0] as Row;

      clickText('History');
      await waitForText('Put this version back');
      clickText('Put this version back');
      await waitForText('Put back the version from');
      clickText('Back');
      await waitForText(/Locks after/);
      clickText('Deleted items');
      await waitForText('Nothing you have deleted');

      // The edge matches a PREFIX TREE, so nothing name-checks these strings —
      // a typo is a 404 in a browser, not a build error.
      const paths = new Set(
        service.calls.map((c) => c.path.split('?')[0] as string).filter((p) => p.includes('items')),
      );
      expect(paths.has('/api/vault/items/restorable')).toBe(true);
      expect(paths.has(`/api/vault/items/${live.id}/versions`)).toBe(true);
      expect(paths.has(`/api/vault/items/${live.id}/restore`)).toBe(true);
    });
  });
});
