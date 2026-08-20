import { RequestMethod } from '@nestjs/common';

/**
 * The route-decorator vocabulary, DERIVED from Nest rather than hand-listed.
 *
 * Two fences in this directory used to carry their own copies. They disagreed:
 * `credential-graph.spec.ts` knew five verbs and `route-consumers.spec.ts`
 * knew nine, and a handler decorated with one the scan did not know derived NO
 * ROUTE AT ALL — silently, in both directions, with no `unparseable` refusal.
 * `@All` is the worst of them: it grants every verb on a
 * service-credential-authenticated route while the sentence a reviewer judges
 * `holders` by says nothing exists there.
 *
 * Nest 11 actually ships SIXTEEN, so the nine-verb list this consolidated on
 * was short by the seven WebDAV verbs — the M21 round-3 review found the five
 * and assumed the nine were complete. Hand-lists rot in the direction of the
 * last person who checked.
 *
 * `RequestMethod` is what Nest's own `@RequestMapping` switches on, so a verb
 * it gains arrives here without an edit.
 */
const VERB_NAMES: readonly string[] = Object.keys(RequestMethod)
  .filter((key) => Number.isNaN(Number(key)))
  .map((key) => key.charAt(0) + key.slice(1).toLowerCase())
  .sort();

export const ROUTE_VERBS: string = VERB_NAMES.join('|');

/** `@Get('path')` / `@Get()` — capturing the verb and the literal path. */
export const routeDecorator = (): RegExp =>
  new RegExp(`@(${ROUTE_VERBS})\\(\\s*(?:'([^']*)')?\\s*\\)`, 'g');

/** Any opener, including the forms the capturing pattern deliberately refuses. */
export const routeDecoratorOpener = (): RegExp => new RegExp(`@(?:${ROUTE_VERBS})\\(`, 'g');

export const ROUTE_VERB_NAMES: readonly string[] = VERB_NAMES;
