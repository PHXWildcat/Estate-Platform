/**
 * WHAT IS INSIDE A VAULT ITEM — and why the server has never seen this file.
 *
 * `vault_items` stores an `item_type` enum, timestamps, and an opaque blob.
 * Everything a person would recognise — the title, the username, the password,
 * the note — lives INSIDE that blob, encrypted under the master key on this
 * device. That is the Zone A trade the service's own docstring names: the
 * client decrypts locally to render a list, which is why blobs are size-capped
 * and the list is paginated.
 *
 * It is also why the title is NOT a column here, unlike `assets_view.title` and
 * `documents.title`, which are accepted plaintext label metadata (2026-07-23).
 * Those are Zone B. A vault item's title is "Chase — joint account" or the name
 * of a therapist's patient portal, and the whole promise of this zone is that a
 * database dump yields none of it.
 *
 * The encoding is JSON, canonicalised through a declared field order so that
 * two clients producing the same item produce the same bytes. Fields are
 * OPTIONAL and unknown ones are PRESERVED on decrypt: a client that has not
 * learned about a field a newer one wrote must not silently drop it on the next
 * save, which would be data loss disguised as an edit.
 */

/** The fields this version of the client understands. */
export interface ItemContent {
  /** What the user calls this. Never a column, never plaintext at rest. */
  title: string;
  username?: string;
  secret?: string;
  url?: string;
  notes?: string;
  /**
   * Anything a NEWER client wrote that this one does not know about, carried
   * through an edit untouched. Without it, opening an item in an older tab and
   * saving would delete fields the user never saw.
   */
  unknown?: Readonly<Record<string, unknown>>;
}

const KNOWN_FIELDS = ['title', 'username', 'secret', 'url', 'notes'] as const;

/** Bytes for the blob. Field order is written out, never `Object.keys`. */
export function encodeItemContent(content: ItemContent): Uint8Array {
  const out: Record<string, unknown> = { ...(content.unknown ?? {}) };
  for (const field of KNOWN_FIELDS) {
    const value = content[field];
    // An empty string is an absent field, not a stored empty value: it keeps
    // the blob (and therefore its size, the one thing the server can measure)
    // from carrying the shape of a form the user left blank.
    if (typeof value === 'string' && value.length > 0) {
      out[field] = value;
    }
  }
  return new TextEncoder().encode(JSON.stringify(out));
}

export class ItemContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ItemContentError';
  }
}

/**
 * Parse a decrypted blob.
 *
 * Throws rather than guessing. A blob that decrypted but does not parse means
 * the AEAD authenticated bytes this client cannot read — a version it does not
 * know — and rendering a blank item over it would invite the user to overwrite
 * something real.
 */
export function decodeItemContent(bytes: Uint8Array): ItemContent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new ItemContentError('item content is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ItemContentError('item content is not an object');
  }
  const record = parsed as Record<string, unknown>;
  const known = new Set<string>(KNOWN_FIELDS);
  const unknown: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (!known.has(key)) {
      unknown[key] = value;
    }
  }

  const text = (field: (typeof KNOWN_FIELDS)[number]): string | undefined => {
    const value = record[field];
    return typeof value === 'string' && value.length > 0 ? value : undefined;
  };

  const title = text('title');
  const content: ItemContent = { title: title ?? '' };
  for (const field of ['username', 'secret', 'url', 'notes'] as const) {
    const value = text(field);
    if (value !== undefined) {
      content[field] = value;
    }
  }
  if (Object.keys(unknown).length > 0) {
    content.unknown = unknown;
  }
  return content;
}
