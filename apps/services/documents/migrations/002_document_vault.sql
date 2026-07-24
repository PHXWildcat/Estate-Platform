-- Document service — M4 PR2: the upload-facing vault's encrypted search index.
--
-- document_search_tokens is a DERIVED, REBUILDABLE projection of encrypted
-- content (title + OCR/rendered text reduced to per-user-keyed HMAC tokens),
-- in the same conventions category as assets_view (docs/02 §8): it is not a
-- business table, carries no history of its own — the authoritative data is
-- the encrypted content artifact — and re-indexing REPLACES a document's
-- rows in place. It is therefore exempt from the soft-delete/_versions
-- conventions (asserted by custom checks in documents.int.spec.ts).
--
-- Privacy properties:
--   * token_bidx = HMAC(user-scoped key, normalized token); the per-user key
--     is derived from SEARCH_INDEX_KEY_HEX, so equal tokens NEVER collide
--     across users (no cross-tenant correlation), and without the index key
--     the column reveals only token counts per document (accepted leak, same
--     rationale as docs/02 §8 blind indexes).
--   * Soft-deleted documents stay indexed but are filtered by the join at
--     query time (no-hard-delete rule); legal erasure purges a document's
--     rows via the privileged retention job alongside its DEK destruction
--     (tokens are derived from content the DEK destruction just erased).
CREATE TABLE document_search_tokens (
  document_id UUID NOT NULL REFERENCES documents(id),
  token_bidx  BYTEA NOT NULL,
  PRIMARY KEY (document_id, token_bidx)
);

CREATE INDEX ix_document_search_tokens_bidx ON document_search_tokens (token_bidx);
