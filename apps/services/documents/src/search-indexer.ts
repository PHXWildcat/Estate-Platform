import { Inject, Injectable } from '@nestjs/common';
import type { DocumentsConfig } from './config';
import { CONFIG } from './di-tokens';
import { indexTokens, MAX_QUERY_TOKENS, searchTokenBidx, tokenize } from './search-index';

/**
 * Injectable face of search-index.ts, bound to the service's configured
 * index key. Produces only HMAC token digests — plaintext tokens never leave
 * this module's callers.
 */
@Injectable()
export class SearchIndexer {
  private readonly key: Buffer;

  constructor(@Inject(CONFIG) config: DocumentsConfig) {
    this.key = config.searchIndexKey;
  }

  /** Token HMACs for a document's searchable text (title + body text). */
  forDocumentText(userId: string, text: string): Buffer[] {
    return indexTokens(this.key, userId, text);
  }

  /** Token HMACs for a search query (bounded term count, AND semantics). */
  forQuery(userId: string, query: string): Buffer[] {
    return tokenize(query, MAX_QUERY_TOKENS).map((token) =>
      searchTokenBidx(this.key, userId, token),
    );
  }
}
