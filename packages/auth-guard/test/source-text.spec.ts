/**
 * The comment stripper every fence in this package reads its corpus through.
 *
 * These cases are not hypothetical: each is a construct that defeated the
 * hand-rolled `source.replace(/\/\*[\s\S]*?\*\//g, '')` this replaced, and each
 * defeated it SILENTLY — the fence went green over a decoration it could no
 * longer see. The naive spelling is asserted alongside so the fixture is known
 * to reach the branch: a case where both strippers agree proves nothing about
 * the fix, and this file would otherwise be a row of tautologies.
 */
import { stripComments } from './source-text';

/** Verbatim the spelling that used to live in three fences in this directory. */
function naive(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
}

const count = (source: string): number => (source.match(/@AllowSessionAudiences\b/g) ?? []).length;

describe('stripComments', () => {
  /**
   * The M21 round-3 evasion. The `/*` lives in a CSP header value on the
   * handler ABOVE; the phantom comment it opens runs to the next real closer,
   * which is the JSDoc of the handler BELOW — so the decoration between them
   * is deleted from the corpus and the reconciliation still balances.
   */
  const EVASION = `
  /** Handler A. */
  @Get('a')
  @Header('Content-Security-Policy', "img-src https://cdn.example.com/*")
  a() {}

  @AllowSessionAudiences('operator')
  @Get('b')
  b() {}

  /** Handler C. */
  @Get('c')
  c() {}
`;

  it.each([
    ['a /* inside a string literal', EVASION],
    [
      'a /* inside a template literal',
      '\nconst p = `a/*b`;\n@AllowSessionAudiences(`operator`)\n/** doc */\nx() {}',
    ],
    [
      'a /* inside a regex literal',
      '\nconst re = /a\\/*b/;\n@AllowSessionAudiences("operator")\n/** doc */\nx() {}',
    ],
  ])('keeps a decoration hidden behind %s — which the naive stripper ate', (_label, source) => {
    // The control: the fixture genuinely reaches the defect.
    expect({ stripper: 'naive', decorations: count(naive(source)) }).toEqual({
      stripper: 'naive',
      decorations: 0,
    });
    expect({ stripper: 'parsed', decorations: count(stripComments(source)) }).toEqual({
      stripper: 'parsed',
      decorations: 1,
    });
  });

  it.each([
    [
      'a block comment',
      '\n/* prose about @AllowSessionAudiences */\n@AllowSessionAudiences("operator")',
    ],
    [
      'a line comment',
      '\n// prose about @AllowSessionAudiences\n@AllowSessionAudiences("operator")',
    ],
    ['a JSDoc', '\n/** prose about @AllowSessionAudiences */\n@AllowSessionAudiences("operator")'],
  ])('still removes the decorator name when it appears in %s', (_label, source) => {
    // The other direction. A stripper that removed nothing would pass every
    // case above and be useless; this is what makes those cases mean something.
    expect(count(stripComments(source))).toBe(1);
  });

  it('does not move a single line, so file:line in a report still points at the code', () => {
    const source = '/** a\n * multi\n * line\n */\nconst x = 1; // trailing\nconst y = 2;\n';
    expect(stripComments(source).split('\n')).toHaveLength(source.split('\n').length);
    expect(stripComments(source)).toContain('const x = 1;');
    expect(stripComments(source)).not.toContain('trailing');
  });
});
