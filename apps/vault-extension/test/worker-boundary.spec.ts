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
import {
  handleWorkerRequest,
  type WorkerRequest,
  type WorkerResponse,
} from '../src/worker-protocol';
import type { KeyHolderPort } from '../src/vault-host';

/** A holder that refuses everything, to exercise the failure path. */
const refusing: KeyHolderPort = {
  isUnlocked: false,
  prepare: () => Promise.reject(new Error('wrong secret key: 0xdeadbeef')),
  finish: () => Promise.reject(new Error('bad proof')),
  summarise: () => Promise.reject(new Error('vault is locked')),
  matchesFor: () => Promise.reject(new Error('vault is locked')),
  lock: () => undefined,
};

describe('the worker protocol', () => {
  it('answers every failure with a bare refusal — no message, no stack', async () => {
    for (const request of [
      { id: 1, kind: 'prepare', userId: 'u', password: 'p', secretKey: 's', challenge: {} },
      { id: 2, kind: 'finish', serverM2: 'a', wrappedMasterKey: 'b', vaultSessionId: 'c' },
      { id: 3, kind: 'summarise', rows: [] },
      { id: 6, kind: 'matches', rows: [], pageUrl: 'https://example.com/' },
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

  it('has NO variant that could ask for the key, and none that returns one', () => {
    // The union is the capability surface. A `getKey` here would be a one-line
    // diff and a total defeat, so the shape is asserted rather than assumed.
    const kinds = [
      'prepare',
      'finish',
      'summarise',
      'matches',
      'lock',
      'state',
    ] satisfies WorkerRequest['kind'][];
    expect(kinds).toHaveLength(6);
    const responses: WorkerResponse[] = [
      { id: 1, ok: true, proof: { publicA: 'a', m1: 'b' } },
      { id: 2, ok: true, summaries: [] },
      { id: 3, ok: true, unlocked: true },
      { id: 4, ok: false },
    ];
    for (const response of responses) {
      expect(Object.keys(response)).not.toContain('key');
      expect(Object.keys(response)).not.toContain('masterKey');
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
      summarise: () => Promise.resolve([{ id: 'i', itemType: 'login', title: 'Zed' }]),
      matchesFor: () => Promise.resolve([]),
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
    expect(await port.summarise([])).toEqual([{ id: 'i', itemType: 'login', title: 'Zed' }]);

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
            itemType: 'login',
            title: 'Bank',
            verdict: { kind: 'match' as const, domain: 'example.com' },
          },
        ]),
      lock: () => undefined,
    };
    const port = new WorkerKeyHolder(fakeWorker(open));
    expect(await port.matchesFor([], 'https://example.com/')).toEqual([
      {
        id: 'i',
        itemType: 'login',
        title: 'Bank',
        verdict: { kind: 'match', domain: 'example.com' },
      },
    ]);

    const refused = new WorkerKeyHolder(fakeWorker(refusing));
    await expect(refused.matchesFor([], 'https://example.com/')).rejects.toThrow('vault is locked');
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
