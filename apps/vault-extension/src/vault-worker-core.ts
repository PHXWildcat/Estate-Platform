import { isFillable, matchOrigin, type MatchVerdict } from './origin-match.js';
import {
  decryptItem,
  encryptItem,
  finishUnlock,
  fromBase64,
  prepareUnlock,
  proveUnlock,
  toBase64,
  wipe,
  type UnlockPreparation,
  type UnlockedVault,
} from '/lib/vault-crypto/index.js';

/**
 * THE ONLY PLACE IN THIS EXTENSION THAT HOLDS A KEY — and it is a WORKER.
 *
 * docs/04's M16 decision put keys in an offscreen document, for a lifetime
 * reason: an MV3 service worker is terminated after seconds, and re-running
 * step-up + SRP + a password + a Secret Key on every popup open is not a
 * ceremony anyone would tolerate. An offscreen document with a non-audio reason
 * has no lifetime limit, so it can hold them.
 *
 * PR2a then found that the offscreen `reason` enum is CLOSED and none of its
 * values describes holding vault keys, and the answer taken was to declare
 * `WORKERS` and make it true by moving the blocking SRP maths off-thread.
 * Building it, a better shape appeared: if the WORKER holds the key rather than
 * merely computing for it, `WORKERS` stops being a declaration made true and
 * becomes structurally true — the offscreen document exists to spawn and host
 * this worker, which is exactly what the reason says.
 *
 * It is also stronger. The master key is a non-extractable `CryptoKey` created
 * HERE and it never crosses a boundary: not to the offscreen document, not to
 * the popup, not through `postMessage`. The alternative split — compute here,
 * hold there — would have had to move either a `CryptoKey` (serializable, but
 * relying on that) or the raw master key BYTES across a channel every extension
 * context receives. Neither happens.
 *
 * WHAT THIS FILE MAY NOT DO: reach the network. `api.ts` is the extension's one
 * call site (`test/fences.spec.ts`), so the offscreen host performs every
 * request and passes this module data. That is what keeps "nothing derived from
 * the vault password or the Secret Key leaves the device" checkable — the
 * password and Secret Key arrive here, are consumed by the derivation, and
 * there is no call site in this module through which anything could leave.
 *
 * NO OFFLINE UNLOCK IS POSSIBLE from what this holds: the wrapped master key,
 * the SRP salt and the KDF parameters arrive from the server per unlock and are
 * never stored, so a device with the extension installed and the Secret Key
 * remembered still cannot open a vault without both the password and a live
 * SRP handshake (docs/04: the extension is SERVER-ANCHORED).
 */

/** Server shape of `POST /v1/vault/srp/start`. */
export interface SrpChallenge {
  readonly handshakeId: string;
  readonly srpSalt: string;
  readonly kdfParams: unknown;
  readonly serverPublic: string;
}

/** Server shape of a `vault_items` row. Opaque until opened here. */
export interface VaultItemRow {
  readonly id: string;
  readonly itemType: string;
  readonly blob: string;
  readonly blobVersion: number;
  readonly updatedAt: string;
}

export interface OpenedSummary {
  readonly id: string;
  readonly itemType: string;
  readonly title: string;
  /**
   * The version this summary was read AT (M16 PR4a).
   *
   * An edit sends it back as `If-Match`, which is the whole of the optimistic
   * concurrency: the service compares it to the row it locks and answers 409
   * `version_conflict` if they differ. Re-reading the version at write time
   * instead would make the check pass every time and defeat it, so the number
   * has to travel with the thing the user opened.
   *
   * Not a secret — a monotonic counter the service already returns on every
   * list.
   */
  readonly blobVersion: number;
  readonly unreadable?: boolean;
}

/** A summary plus why it is being shown for a particular page. */
export interface MatchedSummary extends OpenedSummary {
  readonly verdict: MatchVerdict;
}

/**
 * The decoded content envelope, or null when it is not one.
 *
 * An ARRAY passes a bare `typeof === 'object'` check, so it is refused here for
 * the same reason `titleOf` refuses it: "a record with no fields" and "content
 * this build cannot read" are different facts.
 */
function contentOf(plaintext: Uint8Array): Record<string, unknown> | null {
  const decoded: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) return null;
  return decoded as Record<string, unknown>;
}

/** The item's own `url`, which never leaves this module. */
function urlOf(plaintext: Uint8Array): string | undefined {
  const decoded: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) return undefined;
  const { url } = decoded as { url?: unknown };
  return typeof url === 'string' ? url : undefined;
}

/**
 * The item content envelope, as `vault-web` writes it. Only the TITLE is read
 * here: PR2b lists what a person is choosing between, and the secret half is a
 * PR3 concern that arrives with the gesture requirement governing it.
 */
function titleOf(plaintext: Uint8Array): string {
  const decoded: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  // An ARRAY passes a bare `typeof === 'object'` check, and letting it through
  // would list it as an item with no title — which claims a different fact from
  // the true one. "A record with no title" and "content this build cannot read"
  // are two things a user acts on differently, so they stay apart.
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new Error('unparseable item');
  }
  const { title } = decoded as { title?: unknown };
  return typeof title === 'string' ? title : '';
}

export class VaultKeyHolder {
  #preparation: UnlockPreparation | null = null;
  #session: Awaited<ReturnType<typeof proveUnlock>>['session'] | null = null;
  #vault: UnlockedVault | null = null;
  #userId: string | null = null;

  get isUnlocked(): boolean {
    return this.#vault !== null;
  }

  /**
   * Derive from the password and the Secret Key, and produce the SRP client
   * public value.
   *
   * `prepareUnlock` PINS the parameters the server served before any modular
   * exponentiation (docs/04 M6): Zone A's adversary includes a malicious
   * server, which could otherwise substitute a degenerate group and recover the
   * private key by small-subgroup confinement.
   */
  async prepare(input: {
    userId: string;
    password: string;
    secretKey: string;
    challenge: SrpChallenge;
  }): Promise<{ publicA: string; m1: string }> {
    this.#preparation = await prepareUnlock({
      userId: input.userId,
      password: input.password,
      secretKey: input.secretKey,
      kdfParams: input.challenge.kdfParams,
      srpSalt: input.challenge.srpSalt,
    });
    const { m1, session } = await proveUnlock(this.#preparation, input.challenge.serverPublic);
    this.#session = session;
    this.#userId = input.userId;
    return { publicA: this.#preparation.publicA, m1 };
  }

  /**
   * Verify the server's proof, then unwrap. The ORDER is the point and it is
   * `finishUnlock`'s: a server that could not prove it holds the verifier never
   * gets its `wrappedMasterKey` fed into our unwrap path.
   */
  async finish(input: {
    serverM2: string;
    wrappedMasterKey: string;
    vaultSessionId: string;
  }): Promise<void> {
    if (!this.#preparation || !this.#session) throw new Error('no handshake in progress');
    this.#vault = await finishUnlock({
      preparation: this.#preparation,
      session: this.#session,
      serverM2: input.serverM2,
      wrappedMasterKey: input.wrappedMasterKey,
      vaultSessionId: input.vaultSessionId,
    });
    // The handshake material has done its job. Nothing that could re-derive a
    // key survives the unlock it authorised.
    this.#preparation = null;
    this.#session = null;
  }

  /** Decrypt each row far enough to name it, and no further. */
  async summarise(rows: readonly VaultItemRow[]): Promise<OpenedSummary[]> {
    const vault = this.#vault;
    const userId = this.#userId;
    if (!vault || !userId) throw new Error('vault is locked');
    const out: OpenedSummary[] = [];
    for (const row of rows) {
      const base = { id: row.id, itemType: row.itemType, blobVersion: row.blobVersion };
      let plaintext: Uint8Array | null = null;
      try {
        plaintext = await decryptItem(
          vault.masterKey,
          { userId, itemId: row.id, blobVersion: row.blobVersion },
          fromBase64(row.blob),
        );
        out.push({ ...base, title: titleOf(plaintext) });
      } catch {
        // Either the AEAD refused — a blob that does not belong to this key or
        // this version, which is the anti-rollback binding working — or the
        // content did not parse. Listed as unreadable rather than hidden: a
        // user must be able to see that something is there.
        out.push({ ...base, title: '', unreadable: true });
      } finally {
        if (plaintext) plaintext.fill(0);
      }
    }
    return out;
  }

  /**
   * WHICH SAVED ITEMS RELATE TO THIS PAGE — decided HERE, in the key holder.
   *
   * The item's `url` lives inside the encrypted blob, so this is the only
   * context that can read it. The alternative — hand every item's domain to the
   * popup and match there — would disclose a list of every site the user has an
   * account with in order to answer a question about ONE origin.
   *
   * Returns only what is worth showing: a `match`, or a refusal the user should
   * understand (`confusable`, `scheme-downgrade`). `no-match` and `unusable`
   * are dropped, so the caller learns nothing about items unrelated to the page
   * it asked about. NO SECRET IS RETURNED — that is PR3b's deliberate act.
   */
  async matchesFor(rows: readonly VaultItemRow[], pageUrl: string): Promise<MatchedSummary[]> {
    const vault = this.#vault;
    const userId = this.#userId;
    if (!vault || !userId) throw new Error('vault is locked');
    const out: MatchedSummary[] = [];
    for (const row of rows) {
      let plaintext: Uint8Array | null = null;
      try {
        plaintext = await decryptItem(
          vault.masterKey,
          { userId, itemId: row.id, blobVersion: row.blobVersion },
          fromBase64(row.blob),
        );
        const verdict = matchOrigin(urlOf(plaintext), pageUrl);
        if (verdict.kind === 'no-match' || verdict.kind === 'unusable') continue;
        out.push({
          id: row.id,
          itemType: row.itemType,
          title: titleOf(plaintext),
          blobVersion: row.blobVersion,
          verdict,
        });
      } catch {
        // An unopenable blob cannot be matched against anything, and saying so
        // here would be a claim about an item this build cannot read.
        continue;
      } finally {
        if (plaintext) plaintext.fill(0);
      }
    }
    return out;
  }

  /**
   * SEAL AN ITEM (M16 PR4a) — the first time plaintext travels INTO this module.
   *
   * Until now the traffic was one-way: the password and Secret Key arrive to be
   * consumed by a derivation, and item content only ever comes OUT (`summarise`
   * returns titles, `fillFor` returns one credential). A create or an update
   * reverses that, and two things follow that are worth naming rather than
   * discovering.
   *
   * IT CROSSES A BROADCAST. `chrome.runtime.sendMessage` delivers to every
   * extension context with a listener, so item content transits the same channel
   * the unlock password already does — `messages.ts` calls that "a filter, not
   * an isolation boundary", and it remains true. This adds traffic of an
   * existing class, not a new class: anyone who can read that channel has
   * already compromised the artifact and could ask the worker to decrypt.
   *
   * THE AAD BINDS THE VERSION, so the caller must say which one it is sealing
   * for. `encryptItem` takes `blobVersion` into the AAD (docs/04 M6: create = 1,
   * an update of N encrypts under N+1), which is what stops a blob being
   * replayed into a different version slot. This module refuses to guess it:
   * the number comes from the row the caller read, and an update that does not
   * carry one is a bug rather than a create.
   *
   * NOTHING HERE DECIDES WHETHER THE WRITE IS ALLOWED. That is the vault
   * service's `VaultSessionGuard` plus the `If-Match` the host sends; this
   * module only turns content into ciphertext under the key it holds.
   */
  async sealItem(input: {
    readonly itemId: string;
    readonly blobVersion: number;
    readonly content: Record<string, unknown>;
  }): Promise<string> {
    const vault = this.#vault;
    const userId = this.#userId;
    if (!vault || !userId) throw new Error('vault is locked');
    if (!Number.isInteger(input.blobVersion) || input.blobVersion < 1) {
      throw new Error('blobVersion must be a positive integer');
    }
    const plaintext = new TextEncoder().encode(JSON.stringify(input.content));
    try {
      const blob = await encryptItem(
        vault.masterKey,
        { userId, itemId: input.itemId, blobVersion: input.blobVersion },
        plaintext,
      );
      return toBase64(blob);
    } finally {
      // The caller's copy is theirs to drop; this one is ours.
      plaintext.fill(0);
    }
  }

  /**
   * UPDATE BY MERGING INSIDE THE HOLDER, so an edit needs no read (M16 PR4a).
   *
   * THE OBVIOUS DESIGN WOULD HAVE COST A NEW CAPABILITY. To edit an item a
   * client normally reads it back, shows the fields, and writes the whole thing
   * again — which would mean the popup receiving every item's full plaintext on
   * request. Today it cannot: `summarise` gives titles, and `fillFor` gives ONE
   * credential and only for a page the item actually matches. A general "open
   * this item" variant would make the popup a full vault reader, which is a
   * disclosure widening the milestone has no need to buy.
   *
   * So the merge happens HERE. The caller sends only the fields it is CHANGING;
   * this module decrypts the existing content, applies them, and re-seals. The
   * plaintext it did not send is never sent back to it.
   *
   * ABSENT MEANS UNCHANGED, and it has to: a blank field in a form the user did
   * not fill must not erase a password they cannot see. An explicit empty
   * string is a real value and does clear the field — the same distinction
   * profile's SSN carry makes, for the same reason.
   *
   * Sealed for `blobVersion + 1` because that is what the service will write
   * after checking `If-Match`, and the number is inside the AAD.
   */
  async resealItem(input: {
    readonly rows: readonly VaultItemRow[];
    readonly itemId: string;
    readonly changes: Record<string, unknown>;
  }): Promise<string | null> {
    const vault = this.#vault;
    const userId = this.#userId;
    if (!vault || !userId) throw new Error('vault is locked');
    const row = input.rows.find((candidate) => candidate.id === input.itemId);
    if (!row) return null;

    let plaintext: Uint8Array | null = null;
    try {
      plaintext = await decryptItem(
        vault.masterKey,
        { userId, itemId: row.id, blobVersion: row.blobVersion },
        fromBase64(row.blob),
      );
      const existing = contentOf(plaintext);
      if (!existing) return null;
      // An item this build cannot read must not be silently REPLACED by an edit
      // — that would turn a display problem into data loss.
      const merged = { ...existing, ...input.changes };
      return await this.sealItem({
        itemId: row.id,
        blobVersion: row.blobVersion + 1,
        content: merged,
      });
    } catch {
      return null;
    } finally {
      if (plaintext) plaintext.fill(0);
    }
  }

  /**
   * THE ONE OPERATION THAT LETS A SECRET LEAVE THIS MODULE (M16 PR3b).
   *
   * Every other variant deliberately returns none, and `worker-protocol.ts` has
   * said since PR2b that a fill "will arrive with the gesture requirement that
   * governs it rather than by widening this quietly". This is that arrival, and
   * the shape is what keeps the promise:
   *
   *   · THE CALLER NAMES AN ITEM AND A PAGE, NEVER A SECRET. There is no
   *     "give me item X's password" — the request is "fill X on page P", and
   *     the answer is a credential only if this module agrees the two belong
   *     together. A popup that has been talked into asking cannot ask for more
   *     than a fill it could have driven anyway.
   *   · THE DECISION IS RE-TAKEN HERE, not trusted from the caller. The item's
   *     `url` lives inside the encrypted blob, so this is the only place that
   *     can compare it — and `matchesFor` having already said `match` is not
   *     evidence, because the page can navigate between the two calls.
   *   · ONLY `match` FILLS. `scheme-downgrade` and `confusable` are refusals
   *     with an explanation, and a refusal here returns nothing at all rather
   *     than a reason, on the same grounds as every other worker failure.
   */
  async fillFor(
    rows: readonly VaultItemRow[],
    itemId: string,
    pageUrl: string,
  ): Promise<{ username: string; secret: string } | null> {
    const vault = this.#vault;
    const userId = this.#userId;
    if (!vault || !userId) throw new Error('vault is locked');
    const row = rows.find((candidate) => candidate.id === itemId);
    if (!row) return null;

    let plaintext: Uint8Array | null = null;
    try {
      plaintext = await decryptItem(
        vault.masterKey,
        { userId, itemId: row.id, blobVersion: row.blobVersion },
        fromBase64(row.blob),
      );
      if (!isFillable(matchOrigin(urlOf(plaintext), pageUrl))) return null;
      const content = contentOf(plaintext);
      if (!content) return null;
      return {
        username: typeof content['username'] === 'string' ? content['username'] : '',
        secret: typeof content['secret'] === 'string' ? content['secret'] : '',
      };
    } catch {
      // An unopenable blob fills nothing, and explaining which of the several
      // reasons applied is what this boundary refuses to do everywhere else.
      return null;
    } finally {
      if (plaintext) plaintext.fill(0);
    }
  }

  /**
   * Drop every key.
   *
   * The master key is a non-extractable `CryptoKey`: there are no bytes here to
   * zero, and releasing the last reference is the whole of what this can do
   * about it. Stated rather than implied, because docs/03 §4's "memory
   * zeroization best-effort" must not read as a promise this can keep.
   */
  lock(): void {
    if (this.#vault) wipe(this.#vault.keysetAuthKey);
    this.#vault = null;
    this.#preparation = null;
    this.#session = null;
    this.#userId = null;
  }
}
