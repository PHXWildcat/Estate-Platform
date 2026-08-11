import {
  decryptItem,
  finishUnlock,
  fromBase64,
  prepareUnlock,
  proveUnlock,
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
  readonly unreadable?: boolean;
}

/**
 * The item content envelope, as `vault-web` writes it. Only the TITLE is read
 * here: PR2b lists what a person is choosing between, and the secret half is a
 * PR3 concern that arrives with the gesture requirement governing it.
 */
function titleOf(plaintext: Uint8Array): string {
  const decoded: unknown = JSON.parse(new TextDecoder().decode(plaintext));
  if (typeof decoded !== 'object' || decoded === null) throw new Error('unparseable item');
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
      const base = { id: row.id, itemType: row.itemType };
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
