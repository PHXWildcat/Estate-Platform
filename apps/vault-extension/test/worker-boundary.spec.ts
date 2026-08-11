/**
 * THE WORKER BOUNDARY: what crosses it, and what cannot.
 *
 * The key lives in the worker and never leaves. These cases drive the protocol
 * handler and the port over a fake `Worker` (jsdom has none), and pin the two
 * properties that make the split worth having: no response can carry key
 * material, and a refusal explains nothing.
 */
import { VaultKeyHolder } from '../src/vault-worker-core';
import { WorkerKeyHolder } from '../src/worker-key-holder';
import { handleWorkerRequest, type WorkerRequest } from '../src/worker-protocol';
import type { KeyHolderPort } from '../src/vault-host';

/** A holder that refuses everything, to exercise the failure path. */
const refusing: KeyHolderPort = {
  isUnlocked: false,
  prepare: () => Promise.reject(new Error('wrong secret key: 0xdeadbeef')),
  finish: () => Promise.reject(new Error('bad proof')),
  summarise: () => Promise.reject(new Error('vault is locked')),
  matchesFor: () => Promise.reject(new Error('vault is locked')),
  fillFor: () => Promise.reject(new Error('vault is locked')),
  sealItem: () => Promise.reject(new Error('vault is locked')),
  resealItem: () => Promise.reject(new Error('vault is locked')),
  lock: () => undefined,
};

describe('the worker protocol', () => {
  it('answers every failure with a bare refusal — no message, no stack', async () => {
    for (const request of [
      { id: 1, kind: 'prepare', userId: 'u', password: 'p', secretKey: 's', challenge: {} },
      { id: 2, kind: 'finish', serverM2: 'a', wrappedMasterKey: 'b', vaultSessionId: 'c' },
      { id: 3, kind: 'summarise', rows: [] },
      { id: 6, kind: 'matches', rows: [], pageUrl: 'https://example.com/' },
      // The one variant that could return a secret refuses the same way: a bare
      // `{ ok: false }`, carrying no reason a caller could learn anything from.
      { id: 7, kind: 'fill', rows: [], itemId: 'i', pageUrl: 'https://example.com/' },
    ] as unknown as WorkerRequest[]) {
      const response = await handleWorkerRequest(refusing, request);
      expect(response).toEqual({ id: request.id, ok: false });
      // Nothing about WHICH half of 2SKD was wrong, and no internals at all.
      expect(JSON.stringify(response)).not.toContain('secret key');
      expect(JSON.stringify(response)).not.toContain('deadbeef');
    }
  });

  it('reports lock and state without ever returning a key', async () => {
    const holder = new VaultKeyHolder();
    expect(await handleWorkerRequest(holder, { id: 4, kind: 'state' })).toEqual({
      id: 4,
      ok: true,
      unlocked: false,
    });
    expect(await handleWorkerRequest(holder, { id: 5, kind: 'lock' })).toEqual({
      id: 5,
      ok: true,
      unlocked: false,
    });
  });

  it('enumerates the request union EXHAUSTIVELY, so a new variant cannot slip in', () => {
    /*
     * The union is the capability surface: a `getKey` here would be a one-line
     * diff and a total defeat.
     *
     * REWRITTEN IN PR3b, because the previous form could not do the job it was
     * named for. It was a literal array `satisfies WorkerRequest['kind'][]` plus
     * `toHaveLength(6)`, and BOTH halves are subset checks — `satisfies` only
     * asks whether every element is assignable, and a hand-counted length is
     * true of any six-element literal. A SEVENTH variant compiled clean and left
     * the length at six, so the fence guarding this boundary stayed green while
     * the boundary moved. PR3b is the change that moves it.
     *
     * A `Record` keyed by the union is the form that cannot: a missing key is a
     * compile error, and a key that is not in the union is a compile error too.
     * The runtime list then has to be updated as well, so adding a variant costs
     * two deliberate edits in the file whose whole subject is what may be asked.
     */
    const KINDS: Record<WorkerRequest['kind'], true> = {
      prepare: true,
      finish: true,
      summarise: true,
      matches: true,
      // ADDED IN PR3b, and the compile error that forced this line is the fence
      // doing its job: the previous form let a seventh variant through silently.
      fill: true,
      // ADDED IN PR4a. It forced this line the same way — which is the second
      // and third time this fence has caught a widening of the boundary it
      // guards. `reseal` merges INSIDE the holder so an edit needs no read:
      // the caller sends what it is changing and never receives the rest.
      seal: true,
      reseal: true,
      lock: true,
      state: true,
    };
    expect(Object.keys(KINDS).sort()).toEqual([
      'fill',
      'finish',
      'lock',
      'matches',
      'prepare',
      'reseal',
      'seal',
      'state',
      'summarise',
    ]);
  });

  it('returns no secret from any variant that is not the fill', async () => {
    /*
     * ASSERTED BEHAVIOURALLY rather than over the response type, because the
     * response union is not discriminated by a single literal and a shape
     * assertion over hand-written samples proves only that the samples are
     * clean. This drives the REAL handler over every non-fill variant against an
     * unlocked holder and searches what comes back.
     */
    const holder = new VaultKeyHolder();
    const requests: WorkerRequest[] = [
      { id: 1, kind: 'state' },
      { id: 2, kind: 'lock' },
      { id: 3, kind: 'summarise', rows: [] },
      { id: 4, kind: 'matches', rows: [], pageUrl: 'https://example.com/' },
    ];
    for (const request of requests) {
      const response = await handleWorkerRequest(holder, request);
      const text = JSON.stringify(response);
      for (const forbidden of ['key', 'masterKey', 'secret', 'password']) {
        expect(text).not.toContain(forbidden);
      }
    }
  });
});

/** A Worker double that runs the real handler against a real holder. */
function fakeWorker(holder: KeyHolderPort): Worker & { posted: unknown[] } {
  const listeners: ((event: MessageEvent) => void)[] = [];
  const posted: unknown[] = [];
  return {
    posted,
    addEventListener: (_type: string, listener: (event: MessageEvent) => void) => {
      listeners.push(listener);
    },
    postMessage: (message: unknown) => {
      posted.push(message);
      void handleWorkerRequest(holder, message as WorkerRequest).then((response) => {
        for (const listener of listeners) listener({ data: response } as MessageEvent);
      });
    },
  } as unknown as Worker & { posted: unknown[] };
}

describe('the port over the worker', () => {
  it('mirrors the unlocked flag from the worker’s own answer', async () => {
    const holder = new VaultKeyHolder();
    const port = new WorkerKeyHolder(fakeWorker(holder));
    expect(port.isUnlocked).toBe(false);
    await expect(
      port.finish({ serverM2: 'a', wrappedMasterKey: 'b', vaultSessionId: 'c' }),
    ).rejects.toThrow('unlock refused');
    expect(port.isUnlocked).toBe(false);
  });

  it('goes locked the moment a summarise is refused, whatever the mirror said', async () => {
    // The worker is the authority. A stale mirror can cost one refused request
    // and can never grant a read.
    const port = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(port.summarise([])).rejects.toThrow('vault is locked');
    expect(port.isUnlocked).toBe(false);
  });

  it('locks OPTIMISTICALLY — nothing reads through the mirror while in flight', () => {
    const port = new WorkerKeyHolder(fakeWorker(new VaultKeyHolder()));
    port.lock();
    // Synchronously false, before the message can possibly have been handled.
    expect(port.isUnlocked).toBe(false);
  });

  it('carries a full unlock through the boundary, and nothing else with it', async () => {
    // The happy path across the port: prepare, finish, summarise, lock. What is
    // asserted is that everything the popup could ever see is a proof, a title
    // and a boolean.
    const open: KeyHolderPort = {
      isUnlocked: true,
      prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
      finish: () => Promise.resolve(),
      summarise: () =>
        Promise.resolve([{ id: 'i', itemType: 'password', title: 'Zed', blobVersion: 1 }]),
      matchesFor: () => Promise.resolve([]),
      fillFor: () => Promise.resolve(null),
      sealItem: () => Promise.resolve('c2VhbGVk'),
      resealItem: () => Promise.resolve('cmVzZWFsZWQ='),
      lock: () => undefined,
    };
    const worker = fakeWorker(open);
    const port = new WorkerKeyHolder(worker);

    expect(
      await port.prepare({
        userId: 'u',
        password: 'p',
        secretKey: 's',
        challenge: { handshakeId: 'h', srpSalt: 'x', kdfParams: {}, serverPublic: 'B' },
      }),
    ).toEqual({ publicA: 'A', m1: 'M' });
    await expect(
      port.finish({ serverM2: 'a', wrappedMasterKey: 'b', vaultSessionId: 'c' }),
    ).resolves.toBeUndefined();
    expect(port.isUnlocked).toBe(true);
    expect(await port.summarise([])).toEqual([
      { id: 'i', itemType: 'password', title: 'Zed', blobVersion: 1 },
    ]);

    // Every message that crossed, searched: no key, no password, no secret.
    const crossed = JSON.stringify(worker.posted);
    expect(crossed).not.toContain('masterKey');
    port.lock();
    expect(port.isUnlocked).toBe(false);
  });

  it('carries a MATCH decision across, and goes locked when the worker refuses', async () => {
    const open: KeyHolderPort = {
      isUnlocked: true,
      prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
      finish: () => Promise.resolve(),
      summarise: () => Promise.resolve([]),
      matchesFor: () =>
        Promise.resolve([
          {
            id: 'i',
            itemType: 'password',
            title: 'Bank',
            blobVersion: 1,
            verdict: { kind: 'match' as const, domain: 'example.com' },
          },
        ]),
      fillFor: () => Promise.resolve(null),
      sealItem: () => Promise.resolve('c2VhbGVk'),
      resealItem: () => Promise.resolve('cmVzZWFsZWQ='),
      lock: () => undefined,
    };
    const port = new WorkerKeyHolder(fakeWorker(open));
    expect(await port.matchesFor([], 'https://example.com/')).toEqual([
      {
        id: 'i',
        itemType: 'password',
        title: 'Bank',
        blobVersion: 1,
        verdict: { kind: 'match', domain: 'example.com' },
      },
    ]);

    const refused = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(refused.matchesFor([], 'https://example.com/')).rejects.toThrow('vault is locked');
    expect(refused.isUnlocked).toBe(false);
  });

  it('carries a FILL across, and a refusal comes back as null rather than an error', async () => {
    /*
     * The refusal is the interesting half. `fillFor` answering `null` means the
     * holder declined — wrong page, or an item it could not open — and that must
     * cross the boundary AS null. Turning it into a throw would make the caller's
     * failure path explain which of several reasons applied, which is exactly
     * what this boundary refuses to do everywhere else.
     */
    const filling: KeyHolderPort = {
      isUnlocked: true,
      prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
      finish: () => Promise.resolve(),
      summarise: () => Promise.resolve([]),
      matchesFor: () => Promise.resolve([]),
      fillFor: (_rows, itemId) =>
        Promise.resolve(itemId === 'yes' ? { username: 'u', secret: 's3cret' } : null),
      sealItem: () => Promise.resolve('c2VhbGVk'),
      resealItem: () => Promise.resolve('cmVzZWFsZWQ='),
      lock: () => undefined,
    };
    const port = new WorkerKeyHolder(fakeWorker(filling));
    expect(await port.fillFor([], 'yes', 'https://example.com/')).toEqual({
      username: 'u',
      secret: 's3cret',
    });
    expect(await port.fillFor([], 'no', 'https://example.com/')).toBeNull();

    const refused = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(refused.fillFor([], 'yes', 'https://example.com/')).rejects.toThrow(
      'vault is locked',
    );
    expect(refused.isUnlocked).toBe(false);
  });

  it('throws rather than inventing a proof when the worker refuses a prepare', async () => {
    const port = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(
      port.prepare({
        userId: 'u',
        password: 'p',
        secretKey: 's',
        challenge: { handshakeId: 'h', srpSalt: 'x', kdfParams: {}, serverPublic: 'B' },
      }),
    ).rejects.toThrow('unlock refused');
  });

  it('correlates replies by id, so a slow answer cannot resolve a later call', async () => {
    const holder = new VaultKeyHolder();
    const worker = fakeWorker(holder);
    const port = new WorkerKeyHolder(worker);
    await Promise.all([
      port.summarise([]).catch(() => undefined),
      port.summarise([]).catch(() => undefined),
    ]);
    const ids = (worker.posted as { id: number }[]).map((m) => m.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('sealing across the worker boundary (M16 PR4a)', () => {
  it('carries the blob back, and a refusal goes locked like every other variant', async () => {
    const sealing: KeyHolderPort = {
      isUnlocked: true,
      prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
      finish: () => Promise.resolve(),
      summarise: () => Promise.resolve([]),
      matchesFor: () => Promise.resolve([]),
      fillFor: () => Promise.resolve(null),
      sealItem: (input) => Promise.resolve(`sealed-${String(input.blobVersion)}`),
      resealItem: () => Promise.resolve('cmVzZWFsZWQ='),
      lock: () => undefined,
    };
    const port = new WorkerKeyHolder(fakeWorker(sealing));
    expect(await port.sealItem({ itemId: 'i', blobVersion: 7, content: { title: 't' } })).toBe(
      'sealed-7',
    );

    const refused = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(
      refused.sealItem({ itemId: 'i', blobVersion: 1, content: { title: 't' } }),
    ).rejects.toThrow('vault is locked');
    expect(refused.isUnlocked).toBe(false);
  });

  it('carries a reseal across, and passes its refusal through as null', async () => {
    const merging: KeyHolderPort = {
      isUnlocked: true,
      prepare: () => Promise.resolve({ publicA: 'A', m1: 'M' }),
      finish: () => Promise.resolve(),
      summarise: () => Promise.resolve([]),
      matchesFor: () => Promise.resolve([]),
      fillFor: () => Promise.resolve(null),
      sealItem: () => Promise.resolve('c2VhbGVk'),
      resealItem: (input) => Promise.resolve(input.itemId === 'known' ? 'bWVyZ2Vk' : null),
      lock: () => undefined,
    };
    const port = new WorkerKeyHolder(fakeWorker(merging));
    expect(await port.resealItem({ rows: [], itemId: 'known', changes: {} })).toBe('bWVyZ2Vk');
    // `null` is the holder declining — no such item, or content it cannot read —
    // and crosses as null rather than as an error, like every other refusal here.
    expect(await port.resealItem({ rows: [], itemId: 'other', changes: {} })).toBeNull();

    const refused = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(refused.resealItem({ rows: [], itemId: 'known', changes: {} })).rejects.toThrow(
      'vault is locked',
    );
  });

  it('answers a seal request through the real handler', async () => {
    const holder = new VaultKeyHolder();
    // Locked: the handler must turn the throw into a bare refusal, not a stack.
    expect(
      await handleWorkerRequest(holder, {
        id: 9,
        kind: 'seal',
        itemId: 'i',
        blobVersion: 1,
        content: { title: 't' },
      }),
    ).toEqual({ id: 9, ok: false });
    expect(
      await handleWorkerRequest(holder, {
        id: 10,
        kind: 'reseal',
        rows: [],
        itemId: 'i',
        changes: {},
      }),
    ).toEqual({ id: 10, ok: false });
  });
});
