import { blindIndex } from '@estate/crypto';

/**
 * The encrypted search index (docs/01 §2.6 "OCR + encrypted search index",
 * scoped to Postgres for M4 — OpenSearch is a later milestone).
 *
 * Documents' searchable text (title + rendered/OCR content) is reduced to
 * normalized keyword tokens and stored ONLY as HMACs under a key derived per
 * user from the service's search-index key. Search runs the same reduction
 * over the query and matches ciphertext-side — content is never decrypted to
 * serve a search.
 *
 * Key schedule: userKey = HMAC(masterKey, 'docsearch.userkey.v1', userId);
 * token = HMAC(userKey, 'docsearch.token.v1', normalizedToken). Both steps
 * reuse @estate/crypto's blindIndex (domain-separated HMAC-SHA-256), so an
 * index value can never be compared across users or against another blind
 * index column.
 */

const TOKEN_MIN = 3;
const TOKEN_MAX = 40;
export const MAX_TOKENS_PER_DOCUMENT = 2000;
export const MAX_QUERY_TOKENS = 10;

/**
 * Reduce free text to normalized, deduplicated keyword tokens: NFKC fold,
 * lowercase, split on non-alphanumerics, bounded length and count. The SAME
 * function serves indexing and querying — matching depends on it.
 */
export function tokenize(text: string, cap: number = MAX_TOKENS_PER_DOCUMENT): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of text
    .normalize('NFKC')
    .toLowerCase()
    .split(/[^a-z0-9]+/)) {
    if (raw.length < TOKEN_MIN || raw.length > TOKEN_MAX || seen.has(raw)) {
      continue;
    }
    seen.add(raw);
    out.push(raw);
    if (out.length >= cap) {
      break;
    }
  }
  return out;
}

/** Per-user index key — cross-user token correlation is cryptographically out. */
export function userSearchKey(masterKey: Buffer, userId: string): Buffer {
  return blindIndex(masterKey, 'docsearch.userkey.v1', userId);
}

export function searchTokenBidx(masterKey: Buffer, userId: string, token: string): Buffer {
  return blindIndex(userSearchKey(masterKey, userId), 'docsearch.token.v1', token);
}

/** Tokenize + HMAC a document's searchable text for one user. */
export function indexTokens(masterKey: Buffer, userId: string, text: string): Buffer[] {
  return tokenize(text).map((token) => searchTokenBidx(masterKey, userId, token));
}

/**
 * Plain text of the renderer's canonical HTML, for indexing generated
 * documents through the same pipeline as OCR text. Tags become whitespace;
 * the five entities the renderer's escaper produces are folded back.
 */
export function htmlToText(html: string): string {
  return html
    .replace(/<[^>]*>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}
