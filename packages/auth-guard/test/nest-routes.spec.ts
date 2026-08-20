/**
 * The derived route vocabulary is only trustworthy if the derivation is.
 * These assert the two ways it could rot into silence: Nest renaming the enum
 * out from under it, and the mapping producing a name that is not actually a
 * decorator.
 */
import * as nest from '@nestjs/common';

import { ROUTE_VERB_NAMES, routeDecorator } from './nest-routes';

describe('the route-decorator vocabulary', () => {
  it('names only things @nestjs/common really exports as decorators', () => {
    const notDecorators = ROUTE_VERB_NAMES.filter(
      (name) => typeof (nest as unknown as Record<string, unknown>)[name] !== 'function',
    );
    expect(notDecorators).toEqual([]);
  });

  it('covers every verb the nine-verb hand-list knew, and the seven it did not', () => {
    // The old hand-list, verbatim. Anything here that the derivation lost is a
    // regression; the WebDAV seven are what it GAINED.
    const HAND_LISTED = [
      'Get',
      'Put',
      'Post',
      'Patch',
      'Delete',
      'All',
      'Head',
      'Options',
      'Search',
    ];
    expect(HAND_LISTED.filter((verb) => !ROUTE_VERB_NAMES.includes(verb))).toEqual([]);
    expect(ROUTE_VERB_NAMES).toContain('Propfind');
  });

  it('has an anti-vacuity floor: a derivation that collapsed would match nothing', () => {
    // If `RequestMethod` ever stops being a string-keyed enum this list goes
    // empty, every route-deriving fence in the package silently collects zero,
    // and every one of them passes. That failure is louder here than there.
    expect(ROUTE_VERB_NAMES.length).toBeGreaterThanOrEqual(9);
  });

  it('actually matches a decoration', () => {
    const found = [...`@All('drain')\n@Get()\n@Propfind('x')`.matchAll(routeDecorator())].map(
      (m) => m[1],
    );
    expect(found).toEqual(['All', 'Get', 'Propfind']);
  });
});
