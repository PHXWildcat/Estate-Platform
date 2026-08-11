import { request, type ApiResult } from './api.js';
import type { ItemSummary, VaultState } from './messages.js';
import type {
  MatchedSummary,
  OpenedSummary,
  SrpChallenge,
  VaultItemRow,
} from './vault-worker-core.js';

/**
 * THE OFFSCREEN DOCUMENT'S JOB: everything about an unlock EXCEPT the keys.
 *
 * It performs the network calls, sequences the SRP legs, holds the opaque
 * vault-session token, and runs the idle clock. The key holder it talks to is a
 * WORKER it owns (`vault-worker-core.ts`), which is where the master key lives
 * and where it stays — this module never sees one, and could not use one if it
 * did.
 *
 * THE SPLIT IS WHAT MAKES BOTH FENCES TRUE AT ONCE. `api.ts` must be the
 * extension's only network call site, so the key holder cannot fetch; and only
 * the key holder may import the crypto, so this module cannot decrypt. Each
 * half is missing the capability the other has, and neither is a trust boundary
 * — they are one signed artifact — but the shape means a reviewer auditing "can
 * anything derived from the password leave the device" has one file to read.
 *
 * The port is injectable so the suite can drive a REAL `VaultKeyHolder` in
 * process. jsdom has no `Worker`, and a test that stubbed the crypto could not
 * tell an unlock from a fixture agreeing with itself.
 */

/**
 * How long the vault stays open with no interaction.
 *
 * FIFTEEN MINUTES, matching the server's own `VAULT_SESSION_TTL_MS` — and the
 * match is the point rather than a coincidence. The server session cannot be
 * renewed (docs/04), so a longer client clock would leave the popup showing an
 * unlocked vault whose next read is going to fail, and a shorter one would lock
 * a device that could still work. docs/04 records this as configurable 1–60;
 * the control needs a settings surface, which arrives with one, so it is a
 * reviewed constant until then rather than a number nobody can see.
 */
export const IDLE_LOCK_MS = 15 * 60 * 1000;

/** What the host needs of the key holder. `VaultKeyHolder` satisfies it. */
export interface KeyHolderPort {
  readonly isUnlocked: boolean;
  prepare(input: {
    userId: string;
    password: string;
    secretKey: string;
    challenge: SrpChallenge;
  }): Promise<{ publicA: string; m1: string }>;
  finish(input: {
    serverM2: string;
    wrappedMasterKey: string;
    vaultSessionId: string;
  }): Promise<void>;
  summarise(rows: readonly VaultItemRow[]): Promise<OpenedSummary[]>;
  matchesFor(rows: readonly VaultItemRow[], pageUrl: string): Promise<MatchedSummary[]>;
  lock(): void;
}

/** Server shape of `POST /v1/vault/srp/verify`. */
interface VaultOpened {
  serverProof?: unknown;
  wrappedMasterKey?: unknown;
  vaultSession?: { id?: unknown; token?: unknown; expiresAt?: unknown };
}

interface VaultItemPage {
  items?: unknown;
}

export interface VaultHostOptions {
  readonly holder: KeyHolderPort;
  /** Injected so the idle clock is drivable in a test. */
  readonly setTimer?: (run: () => void, ms: number) => number;
  readonly clearTimer?: (handle: number) => void;
}

export class VaultHost {
  readonly #holder: KeyHolderPort;
  readonly #setTimer: (run: () => void, ms: number) => number;
  readonly #clearTimer: (handle: number) => void;
  /**
   * The opaque vault-session token. NOT key material — it authorises item
   * reads at the service and decrypts nothing — but it is still never
   * persisted: it dies with this document, which is what makes an offscreen
   * teardown a LOCK rather than a suspension.
   */
  #token: string | null = null;
  #expiresAt: string | null = null;
  #idle: number | null = null;

  constructor(options: VaultHostOptions) {
    this.#holder = options.holder;
    this.#setTimer = options.setTimer ?? ((run, ms) => globalThis.setTimeout(run, ms) as never);
    this.#clearTimer = options.clearTimer ?? ((handle) => globalThis.clearTimeout(handle));
  }

  get state(): VaultState {
    return this.#holder.isUnlocked && this.#expiresAt !== null
      ? { status: 'unlocked', expiresAt: this.#expiresAt }
      : { status: 'locked' };
  }

  /** Any interaction restarts the idle clock. */
  #touch(): void {
    if (this.#idle !== null) this.#clearTimer(this.#idle);
    this.#idle = this.#setTimer(() => {
      // Local only: the server session expires on its own clock, and a network
      // failure must never leave keys resident.
      this.#dropKeys();
    }, IDLE_LOCK_MS);
  }

  #dropKeys(): void {
    if (this.#idle !== null) {
      this.#clearTimer(this.#idle);
      this.#idle = null;
    }
    this.#holder.lock();
    this.#token = null;
    this.#expiresAt = null;
  }

  /**
   * Open the vault: SRP-6a over two legs, 2SKD on this device.
   *
   * The password and the Secret Key go STRAIGHT to the key holder and appear in
   * no request this method makes — `test/vault-host.spec.ts` drives the whole
   * flow against a recording transport and asserts exactly that.
   */
  async unlock(input: {
    userId: string;
    password: string;
    secretKey: string;
    bearer: string;
  }): Promise<ApiResult<VaultState>> {
    const challenge = await request<SrpChallenge>('/api/vault/srp/start', {
      method: 'POST',
      bearer: input.bearer,
    });
    if (!challenge.ok) return challenge;

    let proof: { publicA: string; m1: string };
    try {
      proof = await this.#holder.prepare({
        userId: input.userId,
        password: input.password,
        secretKey: input.secretKey,
        challenge: challenge.data,
      });
    } catch {
      // A malformed Secret Key throws before any network call. ONE message for
      // both halves of 2SKD: naming which was wrong would tell someone holding
      // a stolen Secret Key that it is the right one (M15 PR2's rule, and the
      // server answers one `srp_failed` for the same reason).
      return { ok: false, code: 'SRP_FAILED' };
    }

    const opened = await request<VaultOpened>('/api/vault/srp/verify', {
      method: 'POST',
      bearer: input.bearer,
      body: {
        handshakeId: challenge.data.handshakeId,
        clientPublic: proof.publicA,
        clientProof: proof.m1,
      },
    });
    if (!opened.ok) return opened;

    // A response missing its fields is NO DATA, never data. Here the cost of
    // getting it wrong is feeding `undefined` into the unwrap path.
    const { serverProof, wrappedMasterKey, vaultSession } = opened.data;
    const id = vaultSession?.id;
    const token = vaultSession?.token;
    const expiresAt = vaultSession?.expiresAt;
    if (
      typeof serverProof !== 'string' ||
      typeof wrappedMasterKey !== 'string' ||
      typeof id !== 'string' ||
      typeof token !== 'string' ||
      typeof expiresAt !== 'string'
    ) {
      return { ok: false, code: 'UNKNOWN' };
    }

    try {
      // The server's proof is verified BEFORE its wrapped master key is fed
      // into the unwrap path — `finishUnlock`'s ordering, restated because it
      // is the point.
      await this.#holder.finish({ serverM2: serverProof, wrappedMasterKey, vaultSessionId: id });
    } catch {
      this.#dropKeys();
      return { ok: false, code: 'SRP_FAILED' };
    }

    this.#token = token;
    this.#expiresAt = expiresAt;
    this.#touch();
    return { ok: true, data: this.state };
  }

  /** List items, opening each blob inside the worker. */
  async list(bearer: string): Promise<ApiResult<readonly ItemSummary[]>> {
    const token = this.#token;
    if (!token || !this.#holder.isUnlocked) {
      return { ok: false, code: 'VAULT_LOCKED' };
    }
    this.#touch();
    const page = await request<VaultItemPage>('/api/vault/items?limit=200', {
      bearer,
      vaultSession: token,
    });
    if (!page.ok) return page;
    const rows = page.data.items;
    if (!Array.isArray(rows)) {
      // An unreachable vault must never look like an empty one.
      return { ok: false, code: 'UNKNOWN' };
    }
    const summaries = await this.#holder.summarise(rows as VaultItemRow[]);
    // Newest first is the server's own order for its cursor; what a person
    // reads should not depend on that being the same thing, so sort by title.
    return {
      ok: true,
      data: [...summaries].sort((a, b) => a.title.localeCompare(b.title)),
    };
  }

  /**
   * WHAT IS SAVED FOR THIS PAGE.
   *
   * The same read as `list`, decided differently: the worker sees each item's
   * url and returns only what relates to the page — matches, and the refusals
   * worth explaining. Nothing about unrelated items crosses back.
   */
  async matchesFor(bearer: string, pageUrl: string): Promise<ApiResult<readonly MatchedSummary[]>> {
    const token = this.#token;
    if (!token || !this.#holder.isUnlocked) return { ok: false, code: 'VAULT_LOCKED' };
    this.#touch();
    const page = await request<VaultItemPage>('/api/vault/items?limit=200', {
      bearer,
      vaultSession: token,
    });
    if (!page.ok) return page;
    const rows = page.data.items;
    if (!Array.isArray(rows)) return { ok: false, code: 'UNKNOWN' };
    return { ok: true, data: await this.#holder.matchesFor(rows as VaultItemRow[], pageUrl) };
  }

  /**
   * Drop every key, then tell the server.
   *
   * LOCAL FIRST, and deliberately: the keys are what matter, and a network
   * failure must never leave them resident. The server call is best effort —
   * its session expires on its own clock regardless.
   */
  async lock(bearer?: string): Promise<void> {
    const token = this.#token;
    this.#dropKeys();
    if (token && bearer) {
      await request('/api/vault/lock', { method: 'POST', bearer, vaultSession: token });
    }
  }
}
