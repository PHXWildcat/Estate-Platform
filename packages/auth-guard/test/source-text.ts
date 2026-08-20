import ts from 'typescript';

/**
 * Blank the COMMENTS out of TypeScript source, leaving every string, template
 * and regex literal exactly where it stood.
 *
 * WHY THIS IS NOT A REGEX. The obvious spelling —
 * `source.replace(/\/\*[\s\S]*?\*\//g, '')` — is copied into two dozen fences
 * in this repo and is wrong in the direction that goes GREEN. A `/*` inside a
 * string opens a comment that runs to the next real closer, and since this
 * codebase puts a JSDoc above every handler a closer is always a few lines
 * away: everything between is deleted from the scan. The M21 round-3 review
 * defeated `countDecorations` with exactly that, hiding an undeclared
 * `@AllowSessionAudiences('operator')` behind a CSP header value ending `/*`
 * on the handler above it.
 *
 * WHY A FULL PARSE AND NOT `ts.createScanner`. The scanner was tried first and
 * MEASURED: it fixes the string and template cases but still fails on a regex
 * literal containing `/*` (`/a\/*b/`), because without parser context it cannot
 * tell a regex from a division and opens a phantom comment that runs to EOF —
 * the same silent, green failure in a rarer costume. `createSourceFile` knows,
 * because the parser decided. Every comment in a file is trivia attached to
 * exactly one token, so walking the tree collects all of them.
 *
 * Comments become SPACES rather than vanishing, so offsets and line numbers
 * still point where they did: a fence that reports `file:line` must not have
 * moved the lines.
 */
export function stripComments(source: string): string {
  const parsed = ts.createSourceFile(
    'fence.ts',
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const ranges: ts.CommentRange[] = [];
  const seen = new Set<string>();

  const collect = (found: readonly ts.CommentRange[] | undefined): void => {
    for (const range of found ?? []) {
      const key = `${String(range.pos)}:${String(range.end)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      ranges.push(range);
    }
  };

  const visit = (node: ts.Node): void => {
    collect(ts.getLeadingCommentRanges(source, node.getFullStart()));
    collect(ts.getTrailingCommentRanges(source, node.getEnd()));
    for (const child of node.getChildren(parsed)) visit(child);
  };
  visit(parsed);

  // Right to left, so an earlier blanking cannot move a later range.
  let out = source;
  for (const range of ranges.sort((a, b) => b.pos - a.pos)) {
    const blanked = out.slice(range.pos, range.end).replace(/[^\n]/g, ' ');
    out = out.slice(0, range.pos) + blanked + out.slice(range.end);
  }
  return out;
}
