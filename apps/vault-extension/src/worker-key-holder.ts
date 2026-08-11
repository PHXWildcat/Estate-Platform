import type { KeyHolderPort } from './vault-host.js';
import type { OpenedSummary, SrpChallenge, VaultItemRow } from './vault-worker-core.js';
import type { WorkerRequest, WorkerResponse } from './worker-protocol.js';

/**
 * Each variant without its correlation id. DISTRIBUTIVE — a plain
 * `Omit<WorkerRequest, 'id'>` collapses a discriminated union into the
 * intersection of its members' keys, so `rows` stops existing and the compiler
 * refuses a request that is perfectly valid.
 */
type WorkerRequestBody = WorkerRequest extends infer T
  ? T extends { id: number }
    ? Omit<T, 'id'>
    : never
  : never;

/**
 * The host's view of the key holder, across a `Worker` boundary.
 *
 * `VaultHost` is written against `KeyHolderPort` so the suite can hand it a
 * real `VaultKeyHolder` in process — jsdom has no `Worker`, and a test that
 * stubbed the crypto could not tell an unlock from a fixture agreeing with
 * itself. In the shipped artifact it gets this instead, and the difference is
 * exactly one `postMessage` hop.
 *
 * `isUnlocked` IS THE AWKWARD PART, and it is worth saying why rather than
 * hiding it. The port exposes it synchronously because the host asks it before
 * every read, and a worker answers asynchronously — so this keeps a MIRROR,
 * updated from the worker's own replies. The mirror is advisory: the worker is
 * the authority, `summarise` fails there if it is locked, and the host treats
 * that failure as locked regardless of what the mirror said. A stale mirror can
 * therefore cost one refused request and can never grant a read.
 */
export class WorkerKeyHolder implements KeyHolderPort {
  readonly #worker: Worker;
  readonly #pending = new Map<number, (response: WorkerResponse) => void>();
  #nextId = 1;
  #unlocked = false;

  constructor(worker: Worker) {
    this.#worker = worker;
    this.#worker.addEventListener('message', (event: MessageEvent) => {
      const response = event.data as WorkerResponse;
      const resolve = this.#pending.get(response.id);
      if (!resolve) return;
      this.#pending.delete(response.id);
      resolve(response);
    });
  }

  get isUnlocked(): boolean {
    return this.#unlocked;
  }

  #send(request: WorkerRequestBody): Promise<WorkerResponse> {
    const id = this.#nextId++;
    return new Promise<WorkerResponse>((resolve) => {
      this.#pending.set(id, resolve);
      this.#worker.postMessage({ ...request, id });
    });
  }

  async prepare(input: {
    userId: string;
    password: string;
    secretKey: string;
    challenge: SrpChallenge;
  }): Promise<{ publicA: string; m1: string }> {
    const response = await this.#send({ kind: 'prepare', ...input });
    if (!response.ok || !('proof' in response)) throw new Error('unlock refused');
    return response.proof;
  }

  async finish(input: {
    serverM2: string;
    wrappedMasterKey: string;
    vaultSessionId: string;
  }): Promise<void> {
    const response = await this.#send({ kind: 'finish', ...input });
    if (!response.ok || !('unlocked' in response)) throw new Error('unlock refused');
    this.#unlocked = response.unlocked;
    if (!this.#unlocked) throw new Error('unlock refused');
  }

  async summarise(rows: readonly VaultItemRow[]): Promise<OpenedSummary[]> {
    const response = await this.#send({ kind: 'summarise', rows });
    if (!response.ok || !('summaries' in response)) {
      // The worker is the authority on whether it is open. A refusal here means
      // it is not, whatever the mirror believed.
      this.#unlocked = false;
      throw new Error('vault is locked');
    }
    return [...response.summaries];
  }

  lock(): void {
    // Optimistic by design: the mirror goes false FIRST, so nothing can read
    // through it while the message is in flight. A `lock` that never arrives
    // leaves the worker holding a key it will drop on teardown, and the host
    // refusing every read in the meantime — which is the safe direction.
    this.#unlocked = false;
    void this.#send({ kind: 'lock' });
  }
}
