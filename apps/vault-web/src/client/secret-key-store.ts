/**
 * THE SECRET KEY'S LIFE ON THIS DEVICE (M15 PR2, docs/03 §4 TB6).
 *
 * 2SKD derives every vault key from the vault password AND a 128-bit Secret
 * Key generated here and never transmitted (docs/04 M6). The password is
 * something the user knows; the Secret Key is something the DEVICE has, and
 * "device-only" in a browser needs stating precisely rather than implying more
 * than it delivers.
 *
 * WHAT THIS ACTUALLY BUYS, said plainly: under XSS on this origin, ANY
 * persisted Secret Key is readable — localStorage and IndexedDB alike. There is
 * no browser primitive that hides bytes from same-origin script. The control is
 * not the storage API; it is the origin's empty dependency tree, its
 * `script-src 'self'`, and its enforced Trusted Types, which exist so that
 * "script running on this origin" stays a thing that does not happen.
 *
 * IndexedDB over localStorage anyway, for two smaller reasons that are real:
 * it stores the raw bytes as an ArrayBuffer rather than a base64 STRING (so no
 * copy sits in the string table waiting to be enumerated), and it is not
 * exposed through the flat `localStorage` key list that extensions and stray
 * `Object.entries` sweeps walk.
 *
 * PERSISTED BY DEFAULT, with an explicit opt-out, and that is a deliberate
 * product judgement rather than a security shortcut. The alternative — retype
 * 26 characters at every unlock — reliably pushes people to keep the Secret Key
 * in a text file on the desktop or a note in their email, which is strictly
 * worse than an IndexedDB record on an origin with this CSP. The vault
 * PASSWORD is never persisted, so a stolen Secret Key alone opens nothing.
 */

const DB_NAME = 'estate-vault';
const DB_VERSION = 1;
const STORE = 'device';
/** One record per user id: a shared device holds one key per account. */
const keyFor = (userId: string): string => `secret-key:${userId}`;

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (): void => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
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
      request.onerror = (): void => reject(request.error ?? new Error('indexeddb request failed'));
    });
  } finally {
    db.close();
  }
}

/**
 * Remember the Secret Key for this account on this device.
 *
 * Stored as raw bytes. Callers pass the parsed entropy rather than the `ES1-…`
 * text so that the human-readable form — the one a user might paste somewhere
 * — exists only for as long as the setup screen shows it.
 */
export async function rememberSecretKey(userId: string, entropy: Uint8Array): Promise<void> {
  // A COPY into a fresh buffer: the caller wipes its own array, and a stored
  // view onto a wiped buffer would silently become zeroes.
  await withStore('readwrite', (store) =>
    store.put(new Uint8Array(entropy).buffer, keyFor(userId)),
  );
}

/** The remembered key, or null when this device has never been told. */
export async function recallSecretKey(userId: string): Promise<Uint8Array | null> {
  let stored: ArrayBuffer | undefined;
  try {
    stored = await withStore<ArrayBuffer | undefined>('readonly', (store) =>
      store.get(keyFor(userId)),
    );
  } catch {
    // A browser with IndexedDB disabled or a private window that refuses it is
    // a device that does not remember, not an error worth surfacing: the unlock
    // screen simply asks for the Secret Key.
    return null;
  }
  return stored ? new Uint8Array(stored) : null;
}

/**
 * Forget it. Called by the explicit control, and by RESET — which destroys the
 * vault this key belonged to, so leaving it behind would offer a key to a lock
 * that no longer exists.
 */
export async function forgetSecretKey(userId: string): Promise<void> {
  try {
    await withStore('readwrite', (store) => store.delete(keyFor(userId)));
  } catch {
    // Best effort: failing to forget must not block the action that asked.
  }
}
