import {
  buildKeysetChange,
  createVaultEnrollment,
  decryptItem,
  encryptItem,
  exportMasterKeyBytes,
  finishUnlock,
  fromBase64,
  parseSecretKey,
  prepareUnlock,
  proveUnlock,
  toBase64,
  wipe,
  type UnlockedVault,
} from '/lib/vault-crypto/index.js';
import { request, type ApiResult } from './api.js';
import { decodeItemContent, encodeItemContent, type ItemContent } from './item-content.js';

/**
 * THE ONLY PLACE IN THIS APP THAT HOLDS A KEY.
 *
 * Everything the vault can do while unlocked runs through this module, and it
 * exists so that "where are the keys" has one answer. What it holds lives in
 * memory only, for the life of one page: the master key as a NON-EXTRACTABLE
 * `CryptoKey` (docs/03 §4 TB6 — an injected script could use it but not read it
 * out), the SRP-derived keyset-auth key, and the opaque vault-session token.
 *
 * None of it is ever persisted, and none of it is ever an argument to
 * `api.ts` — the network module takes a session token and opaque base64, so
 * there is no call shape in which key material could travel even by mistake.
 *
 * WHAT LEAVES THIS DEVICE, exhaustively: an SRP public value and proof, the
 * blobs this module encrypts, and the keyset payload (a verifier and a wrapped
 * master key). The vault password and the Secret Key are inputs to derivation
 * and appear in no request. `test/no-key-material-egress.spec.ts` drives a full
 * enrollment and unlock against a recording transport and asserts exactly that.
 */

/** Server shape of `GET /v1/vault/keyset`. */
interface KeysetStatus {
  enrolled: boolean;
  updatedAt: string | null;
}

interface SrpChallenge {
  handshakeId: string;
  srpSalt: string;
  kdfParams: unknown;
  serverPublic: string;
}

interface VaultOpened {
  serverProof: string;
  wrappedMasterKey: string;
  vaultSession: { id: string; token: string; expiresAt: string };
}

/** Server shape of a `vault_items` row. The blob is opaque until we open it. */
export interface VaultItemDto {
  id: string;
  itemType: string;
  blob: string;
  blobVersion: number;
  createdAt: string;
  updatedAt: string;
}

interface VaultItemPage {
  items: VaultItemDto[];
  nextCursor: string | null;
}

/** An item with its content opened — never sent anywhere in this shape. */
export interface OpenedItem {
  id: string;
  itemType: string;
  blobVersion: number;
  updatedAt: string;
  content: ItemContent;
  /**
   * Set when the blob decrypted but its content could not be parsed. The row is
   * still listed, deliberately: hiding it would leave a user unable to see that
   * something exists, and offering to overwrite it would be worse.
   */
  unreadable?: boolean;
}

/**
 * How long the client keeps keys after the last interaction.
 *
 * SHORTER THAN THE SERVER'S 15 minutes, on purpose. The vault session expires
 * server-side on identity's access-token clock, which bounds what a stolen
 * token is worth; this bounds what an unattended SCREEN is worth, which is the
 * threat a user actually pictures. Five minutes matches the step-up freshness
 * window the rest of the product uses for sensitive actions (docs/01 §5), so a
 * user does not have to learn a second number.
 */
export const IDLE_LOCK_MS = 5 * 60 * 1000;

export type SessionState =
  { status: 'locked' } | { status: 'unlocked'; userId: string; expiresAt: string };

type Listener = (state: SessionState) => void;

export class VaultSession {
  /*
   * `#private` rather than TypeScript `private`, which is erased at compile
   * time and leaves the fields as ordinary enumerable properties — reachable
   * through `Object.values`, a structured logger, or a debugger expression.
   * The M10 privacy-proxy review found exactly that shape and it applies with
   * more force here: these are the keys, not a placeholder map.
   */
  #vault: UnlockedVault | null = null;
  /*
   * Retained ONLY for the password change, which needs the master key BYTES to
   * re-wrap them under a key derived from the new password — and a
   * non-extractable `CryptoKey` cannot be re-wrapped (keyset.ts's
   * `exportMasterKeyBytes` exists for exactly this).
   *
   * Holding the AUK is not a new exposure class: it is derived from the same
   * password and Secret Key as the master key this session already holds, and
   * it lives in the same `#private` field, for the same lifetime, dropped by
   * the same `lock()`. The alternative — a second full SRP unlock inside the
   * change flow — would mint a second server session to immediately revoke.
   */
  #auk: CryptoKey | null = null;
  #wrappedMasterKey: string | null = null;
  /**
   * The current keyset's KDF parameters and SRP salt, kept so a key-changing
   * action can VERIFY the credentials it is handed without a network round
   * trip (M15 review). Neither is secret — the server serves both to anyone who
   * can start an SRP handshake — so retaining them widens nothing; what they
   * buy is the ability to re-derive this vault's AUK locally and check that a
   * typed password and Secret Key actually open it.
   */
  #kdfParams: unknown = null;
  #srpSalt: string | null = null;
  #token: string | null = null;
  #userId: string | null = null;
  #expiresAt: string | null = null;
  #idleTimer: ReturnType<typeof setTimeout> | null = null;
  #listeners = new Set<Listener>();

  get state(): SessionState {
    return this.#vault && this.#userId && this.#expiresAt
      ? { status: 'unlocked', userId: this.#userId, expiresAt: this.#expiresAt }
      : { status: 'locked' };
  }

  get isUnlocked(): boolean {
    return this.#vault !== null;
  }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  #announce(): void {
    const state = this.state;
    for (const listener of this.#listeners) {
      listener(state);
    }
  }

  /** Any interaction restarts the idle clock. */
  touch(): void {
    if (!this.isUnlocked) {
      return;
    }
    if (this.#idleTimer !== null) {
      clearTimeout(this.#idleTimer);
    }
    this.#idleTimer = setTimeout(() => {
      void this.lock('idle');
    }, IDLE_LOCK_MS);
  }

  /** Has this account enrolled a vault? Drives the first screen. */
  async keysetStatus(): Promise<ApiResult<KeysetStatus>> {
    return request<KeysetStatus>('/api/vault/keyset');
  }

  /**
   * First-time enrollment.
   *
   * The Secret Key is generated HERE and returned to the caller exactly once,
   * for the screen to show and the Emergency Kit to carry. It is not stored by
   * this method: whether the device remembers it is the user's explicit choice,
   * made on that screen.
   */
  async enroll(
    userId: string,
    password: string,
  ): Promise<ApiResult<{ secretKey: string; entropy: Uint8Array }>> {
    const { enrollment } = await createVaultEnrollment({ userId, password });
    const created = await request('/api/vault/keyset', {
      method: 'POST',
      body: enrollment.payload,
    });
    if (!created.ok) {
      return created;
    }
    // Parsed here so the caller can offer "remember this device" without
    // re-deriving, and so the human-readable form has one owner.
    const entropy = await parseSecretKey(enrollment.secretKey);
    return { ok: true, data: { secretKey: enrollment.secretKey, entropy } };
  }

  /**
   * Open the vault: SRP-6a over two legs, 2SKD on this device.
   *
   * `prepareUnlock` pins the KDF and SRP parameters the SERVER served before any
   * modular exponentiation (docs/04 M6) — Zone A's adversary includes a
   * malicious server, which could otherwise substitute a degenerate group and
   * recover the private key by small-subgroup confinement.
   */
  async unlock(
    userId: string,
    password: string,
    secretKey: string,
  ): Promise<ApiResult<{ ok: true }>> {
    const challenge = await request<SrpChallenge>('/api/vault/srp/start', { method: 'POST' });
    if (!challenge.ok) {
      return challenge;
    }

    const preparation = await prepareUnlock({
      userId,
      password,
      secretKey,
      kdfParams: challenge.data.kdfParams,
      srpSalt: challenge.data.srpSalt,
    });
    const { m1, session } = await proveUnlock(preparation, challenge.data.serverPublic);

    const opened = await request<VaultOpened>('/api/vault/srp/verify', {
      method: 'POST',
      body: {
        handshakeId: challenge.data.handshakeId,
        clientPublic: preparation.publicA,
        clientProof: m1,
      },
    });
    if (!opened.ok) {
      return opened;
    }

    // The server's proof is verified BEFORE its wrapped master key is fed into
    // our unwrap path (keyset.ts's ordering, restated because it is the point).
    this.#vault = await finishUnlock({
      preparation,
      session,
      serverM2: opened.data.serverProof,
      wrappedMasterKey: opened.data.wrappedMasterKey,
      vaultSessionId: opened.data.vaultSession.id,
    });
    this.#auk = preparation.auk;
    this.#wrappedMasterKey = opened.data.wrappedMasterKey;
    this.#kdfParams = challenge.data.kdfParams;
    this.#srpSalt = challenge.data.srpSalt;
    this.#token = opened.data.vaultSession.token;
    this.#userId = userId;
    this.#expiresAt = opened.data.vaultSession.expiresAt;
    this.touch();
    this.#announce();
    return { ok: true, data: { ok: true } };
  }

  /**
   * Drop every key and tell the server to revoke the session.
   *
   * LOCAL FIRST, and deliberately: the keys are what matter, and a network
   * failure must never leave them resident. The server call is best effort —
   * its session expires on its own clock regardless.
   */
  async lock(reason: 'user' | 'idle' | 'expired' = 'user'): Promise<void> {
    const token = this.#token;
    if (this.#idleTimer !== null) {
      clearTimeout(this.#idleTimer);
      this.#idleTimer = null;
    }
    if (this.#vault) {
      wipe(this.#vault.keysetAuthKey);
    }
    // The master key is a non-extractable CryptoKey: there are no bytes here to
    // zero, and dropping the last reference is the whole of what this client
    // can do about it. Stated rather than implied, because "zeroization
    // best-effort" in docs/03 §4 must not read as a promise this can keep.
    this.#vault = null;
    this.#auk = null;
    this.#wrappedMasterKey = null;
    this.#kdfParams = null;
    this.#srpSalt = null;
    this.#token = null;
    this.#userId = null;
    this.#expiresAt = null;
    this.#announce();
    if (token && reason !== 'expired') {
      await request('/api/vault/lock', { method: 'POST', vaultSession: token });
    }
  }

  #requireOpen(): { vault: UnlockedVault; token: string; userId: string } {
    if (!this.#vault || !this.#token || !this.#userId) {
      throw new Error('vault is locked');
    }
    return { vault: this.#vault, token: this.#token, userId: this.#userId };
  }

  /** List items, opening each blob on this device. */
  async list(): Promise<ApiResult<OpenedItem[]>> {
    const { vault, token, userId } = this.#requireOpen();
    this.touch();
    const page = await request<VaultItemPage>('/api/vault/items?limit=200', {
      vaultSession: token,
    });
    if (!page.ok) {
      return page;
    }
    const opened: OpenedItem[] = [];
    for (const row of page.data.items ?? []) {
      opened.push(await this.#open(vault, userId, row));
    }
    // Newest first. The server orders by `updated_at` for its cursor; the list
    // a person reads should not depend on that being the same thing.
    opened.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    return { ok: true, data: opened };
  }

  async #open(vault: UnlockedVault, userId: string, row: VaultItemDto): Promise<OpenedItem> {
    const base = {
      id: row.id,
      itemType: row.itemType,
      blobVersion: row.blobVersion,
      updatedAt: row.updatedAt,
    };
    try {
      const plaintext = await decryptItem(
        vault.masterKey,
        { userId, itemId: row.id, blobVersion: row.blobVersion },
        fromBase64(row.blob),
      );
      const content = decodeItemContent(plaintext);
      plaintext.fill(0);
      return { ...base, content };
    } catch {
      // Either the AEAD refused (a blob that does not belong to this key or
      // this version — the anti-rollback binding working) or the content did
      // not parse. Both are shown as an unreadable ROW rather than hidden: a
      // user must be able to see that something is there.
      return { ...base, content: { title: '' }, unreadable: true };
    }
  }

  /** Create an item. The id is generated HERE — it is bound into the AAD. */
  async create(itemType: string, content: ItemContent): Promise<ApiResult<VaultItemDto>> {
    const { vault, token, userId } = this.#requireOpen();
    this.touch();
    const itemId = crypto.randomUUID();
    const plaintext = encodeItemContent(content);
    const blob = await encryptItem(vault.masterKey, { userId, itemId, blobVersion: 1 }, plaintext);
    plaintext.fill(0);
    return request<VaultItemDto>('/api/vault/items', {
      method: 'POST',
      vaultSession: token,
      body: { id: itemId, itemType, blob: toBase64(blob) },
    });
  }

  /**
   * Update an item. The new blob is bound by AAD to version N+1 and `If-Match`
   * carries N, so a server that stored it anywhere else would produce an item
   * that no longer decrypts — which is the anti-rollback property, enforced by
   * arithmetic rather than by trust.
   */
  async update(
    item: OpenedItem,
    itemType: string,
    content: ItemContent,
  ): Promise<ApiResult<VaultItemDto>> {
    const { vault, token, userId } = this.#requireOpen();
    this.touch();
    const nextVersion = item.blobVersion + 1;
    const plaintext = encodeItemContent(content);
    const blob = await encryptItem(
      vault.masterKey,
      { userId, itemId: item.id, blobVersion: nextVersion },
      plaintext,
    );
    plaintext.fill(0);
    return request<VaultItemDto>(`/api/vault/items/${item.id}`, {
      method: 'PUT',
      vaultSession: token,
      ifMatch: item.blobVersion,
      body: { itemType, blob: toBase64(blob) },
    });
  }

  /**
   * Change the vault password.
   *
   * Three things have to be true at once, and the service enforces all of them
   * (docs/04 M6): a step-up-fresh account session, an OPEN vault, and an HMAC
   * over the new keyset under the key both sides derived from the SRP session.
   * The proof is what makes replacement require knowledge of the CURRENT
   * password — without it, exfiltrated bearer tokens could overwrite the keyset
   * with a wrapping of a fresh random master key and destroy every item.
   *
   * The SECRET KEY IS UNCHANGED: only the password half of the derivation
   * moves, so a user who changes their password does not get a new Emergency
   * Kit and the old one stays correct.
   */
  async changePassword(
    currentPassword: string,
    newPassword: string,
    secretKey: string,
  ): Promise<ApiResult<unknown>> {
    const { vault, token, userId } = this.#requireOpen();
    if (!this.#auk || !this.#wrappedMasterKey || !this.#srpSalt) {
      throw new Error('vault is locked');
    }
    this.touch();

    /*
     * VERIFY THE CREDENTIALS THIS IS ABOUT TO REBIND THE VAULT TO (M15 review).
     *
     * Before this check, `changePassword` fed whatever Secret Key was typed
     * straight into `buildKeyset`, so a well-formed but WRONG key silently
     * re-derived the AUK and the SRP verifier from it and the screen reported
     * success. Nothing downstream could catch it: the service authorizes the
     * replacement with an HMAC proof derived from the SRP session, which proves
     * knowledge of the CURRENT credentials and — by design, this being
     * zero-knowledge — says nothing about what the NEW payload was built from.
     *
     * So the check has to be here, and it has to be local. Re-deriving this
     * vault's AUK from the typed pair and using it to unwrap the master key we
     * already hold proves BOTH halves at once: `open()` is an AEAD decrypt, so
     * a wrong password or a wrong Secret Key fails authentication rather than
     * returning garbage. That is also why the form now asks for the current
     * password — without it there is nothing to derive from, and a screen that
     * changes key material on the strength of an open tab alone was the weaker
     * design anyway.
     */
    const candidate = await prepareUnlock({
      userId,
      password: currentPassword,
      secretKey,
      kdfParams: this.#kdfParams,
      srpSalt: this.#srpSalt,
    });
    try {
      await exportMasterKeyBytes({
        userId,
        auk: candidate.auk,
        wrappedMasterKey: this.#wrappedMasterKey,
      }).then(wipe);
    } catch {
      // One answer for a wrong password and a wrong Secret Key, matching the
      // unlock screen: naming which half was wrong would tell someone holding a
      // stolen Secret Key that it is the right one (the 2SKD rule).
      return { ok: false, code: 'UNAUTHENTICATED' };
    }
    const masterKeyBytes = await exportMasterKeyBytes({
      userId,
      auk: this.#auk,
      wrappedMasterKey: this.#wrappedMasterKey,
    });
    try {
      const { payload, proof } = await buildKeysetChange({
        userId,
        newPassword,
        secretKey,
        masterKey: masterKeyBytes,
        keysetAuthKey: vault.keysetAuthKey,
      });
      return await request('/api/vault/keyset', {
        method: 'PUT',
        vaultSession: token,
        body: { ...payload, proof },
      });
    } finally {
      // The one moment raw master-key bytes exist in this process.
      wipe(masterKeyBytes);
    }
  }

  /**
   * RESET: the escape hatch for a forgotten password, and a crypto-shred.
   *
   * Deliberately does NOT require an open vault — you cannot unlock a vault
   * whose password you have lost, which is the entire situation this route
   * exists for. The service gates it on step-up instead, and destroys every
   * wrapping of the old master key including the emergency-access escrow (the
   * M6 review's finding).
   *
   * A new keyset means a NEW Secret Key. The old one opens nothing afterwards,
   * so the caller must show it exactly as it does at enrollment.
   */
  async reset(
    userId: string,
    newPassword: string,
  ): Promise<ApiResult<{ secretKey: string; entropy: Uint8Array; itemsDestroyed: number }>> {
    const { enrollment } = await createVaultEnrollment({ userId, password: newPassword });
    const done = await request<{ itemsDestroyed: number }>('/api/vault/reset', {
      method: 'POST',
      body: enrollment.payload,
    });
    if (!done.ok) {
      return done;
    }
    // Whatever this session was holding refers to a key that no longer opens
    // anything.
    await this.lock('expired');
    const entropy = await parseSecretKey(enrollment.secretKey);
    return {
      ok: true,
      data: {
        secretKey: enrollment.secretKey,
        entropy,
        itemsDestroyed: done.data.itemsDestroyed ?? 0,
      },
    };
  }

  /**
   * The master key, for the emergency-access module.
   *
   * Two shapes, because the two operations genuinely need different things: the
   * `CryptoKey` wraps and unwraps the recovery keypair, and the BYTES are what
   * `createEscrow` splits. The caller wipes what it is given — this returns a
   * fresh export each time rather than caching one, so there is no long-lived
   * copy of the raw key anywhere in this process.
   */
  /**
   * The vault-session token, for routes the emergency module calls directly.
   *
   * Exposed rather than duplicated: this token is already on the wire for every
   * item request, so an accessor adds no reachability — while a second copy of
   * the request plumbing inside `emergency.ts` would be a second place for the
   * header name and the lock check to drift.
   */
  requireVaultToken(): string {
    return this.#requireOpen().token;
  }

  requireMasterKey(): CryptoKey {
    return this.#requireOpen().vault.masterKey;
  }

  async exportMasterKey(): Promise<Uint8Array> {
    const { userId } = this.#requireOpen();
    if (!this.#auk || !this.#wrappedMasterKey) {
      throw new Error('vault is locked');
    }
    return exportMasterKeyBytes({
      userId,
      auk: this.#auk,
      wrappedMasterKey: this.#wrappedMasterKey,
    });
  }

  /** Delete. Step-up gated server-side, like every deletion in the product. */
  async remove(itemId: string): Promise<ApiResult<unknown>> {
    const { token } = this.#requireOpen();
    this.touch();
    return request(`/api/vault/items/${itemId}`, { method: 'DELETE', vaultSession: token });
  }
}
