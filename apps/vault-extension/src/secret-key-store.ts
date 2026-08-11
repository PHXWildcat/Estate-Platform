/**
 * THE SECRET KEY'S LIFE ON THIS DEVICE (M16 PR2b, docs/03 §4 TB6 / TB9).
 *
 * 2SKD derives every vault key from the vault password AND a 128-bit Secret Key
 * that is generated on a device and never transmitted. The password is
 * something the user knows; the Secret Key is something the DEVICE has.
 *
 * REMEMBERED BY DEFAULT, WITH AN EXPLICIT OPT-OUT — the same product judgement
 * `vault-web` recorded, taken again here with the differences named rather than
 * inherited. The alternative is retyping 26 characters at every unlock, and
 * with a 15-minute vault session that cannot be renewed, that is many times a
 * day; the reliable result is the Secret Key in a text file on the desktop,
 * which is strictly worse than a record in extension storage.
 *
 * WHAT IS DIFFERENT HERE, and it is why this is a stated residual rather than a
 * copied decision. This artifact ALREADY keeps a 30-day refresh token on disk,
 * so remembering the Secret Key puts two of the three factors on one disk,
 * missing only the password. And unlike the vault origin — whose defence is an
 * empty dependency tree, `script-src 'self'` and enforced Trusted Types — this
 * is a signed artifact auto-updated through a vendor store with no CSP in its
 * path (docs/03 §4 TB9), where a compromised update is undetectable by the
 * platform.
 *
 * WHAT IT STILL DOES NOT BUY AN ATTACKER: an offline unlock. The wrapped master
 * key, the SRP salt and the KDF parameters arrive from the server per unlock and
 * are never stored, so opening a vault needs the password AND a live SRP
 * handshake against a live extension session — which is visible in the owner's
 * paired-devices list and revocable from there in one click.
 *
 * IndexedDB rather than `chrome.storage.local`, for the reason `vault-web`
 * gives: it holds the raw bytes as an ArrayBuffer rather than a base64 STRING,
 * so no copy sits in a string table, and it is not in the flat key list that
 * sweeps walk. Neither hides bytes from code running in this extension — no
 * browser primitive does — and the storage API is not the control.
 */

const DB_NAME = 'estate-vault-extension';
const DB_VERSION = 1;
const STORE = 'device';
/** One record per account: a shared browser profile holds one key per user. */
const keyFor = (userId: string): string => `secret-key:${userId}`;

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (): void => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    request.onsuccess = (): void => resolve(request.result);
    request.onerror = (): void => reject(request.error ?? new Error('indexeddb open failed'));
  });
}

async function withStore<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest,
): Promise<T> {
  const db = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = run(tx.objectStore(STORE));
      request.onsuccess = (): void => resolve(request.result as T);
      request.onerror = (): void => reject(request.error ?? new Error('indexeddb failed'));
    });
  } finally {
    db.close();
  }
}

/**
 * Every read is best effort. A device that cannot reach its store should ask
 * the user to type the key, not refuse to open the vault at all — the failure
 * this must never produce is a user locked out by a storage quirk.
 */
export async function rememberedSecretKey(userId: string): Promise<string | null> {
  try {
    const stored = await withStore<unknown>('readonly', (store) => store.get(keyFor(userId)));
    return typeof stored === 'string' && stored.length > 0 ? stored : null;
  } catch {
    return null;
  }
}

export async function rememberSecretKey(userId: string, secretKey: string): Promise<void> {
  try {
    await withStore('readwrite', (store) => store.put(secretKey, keyFor(userId)));
  } catch {
    // Remembering is a convenience. Failing to remember must not fail the
    // unlock that just succeeded.
  }
}

/**
 * Forget it — the opt-out, and what disconnecting the device does.
 *
 * Called on disconnect as well as on an explicit "do not remember", because a
 * device that is no longer paired has no business holding half of the key
 * material for an account it can no longer reach.
 */
export async function forgetSecretKey(userId: string): Promise<void> {
  try {
    await withStore('readwrite', (store) => store.delete(keyFor(userId)));
  } catch {
    // Nothing to do: the caller is tearing down regardless, and reporting a
    // storage failure here would block a teardown the user asked for.
  }
}
