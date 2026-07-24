import { randomBytes, randomUUID } from 'node:crypto';
import {
  htmlToText,
  indexTokens,
  MAX_TOKENS_PER_DOCUMENT,
  searchTokenBidx,
  tokenize,
  userSearchKey,
} from '../src/search-index';

const KEY = randomBytes(32);
const USER_A = randomUUID();
const USER_B = randomUUID();

describe('tokenize', () => {
  it('normalizes, lowercases, splits, bounds, and dedupes', () => {
    expect(tokenize('The Deed, recorded IN Marlow-County! (2026)')).toEqual([
      'the',
      'deed',
      'recorded',
      'marlow',
      'county',
      '2026',
    ]);
    expect(tokenize('a ab abc')).toEqual(['abc']); // < 3 chars dropped
    expect(tokenize('x'.repeat(41))).toEqual([]); // > 40 chars dropped
    expect(tokenize('deed deed DEED')).toEqual(['deed']);
    expect(tokenize('Ｄｅｅｄ')).toEqual(['deed']); // NFKC folds full-width
  });

  it('caps token count', () => {
    const many = Array.from({ length: MAX_TOKENS_PER_DOCUMENT + 100 }, (_, i) => `tok${i}`).join(
      ' ',
    );
    expect(tokenize(many)).toHaveLength(MAX_TOKENS_PER_DOCUMENT);
  });
});

describe('per-user keyed token HMACs', () => {
  it('same token, same user ⇒ same digest; different user ⇒ different digest', () => {
    const a1 = searchTokenBidx(KEY, USER_A, 'deed');
    const a2 = searchTokenBidx(KEY, USER_A, 'deed');
    const b = searchTokenBidx(KEY, USER_B, 'deed');
    expect(a1.equals(a2)).toBe(true);
    expect(a1.equals(b)).toBe(false);
  });

  it('user keys are domain-separated from token digests', () => {
    expect(userSearchKey(KEY, USER_A).equals(searchTokenBidx(KEY, USER_A, USER_A))).toBe(false);
  });

  it('indexTokens digests exactly the tokenizer output', () => {
    const digests = indexTokens(KEY, USER_A, 'Deed recorded');
    expect(digests).toHaveLength(2);
    expect(digests[0]!.equals(searchTokenBidx(KEY, USER_A, 'deed'))).toBe(true);
    expect(digests[1]!.equals(searchTokenBidx(KEY, USER_A, 'recorded'))).toBe(true);
  });
});

describe('htmlToText', () => {
  it('strips tags and folds the renderer-produced entities', () => {
    expect(htmlToText('<h1>Will</h1><p>Smith &amp; Jones &lt;LLP&gt; &quot;&#39;</p>')).toBe(
      ' Will  Smith & Jones <LLP> "\' ',
    );
  });

  it('never double-unescapes: literal entity text survives one fold', () => {
    // A document literally containing "&lt;" renders as "&amp;lt;"; folding
    // must yield the original "&lt;", not "<" (CodeQL js/double-escaping).
    expect(htmlToText('<p>A &amp;lt; B</p>')).toBe(' A &lt; B ');
    expect(htmlToText('<p>&amp;amp;</p>')).toBe(' &amp; ');
  });
});
