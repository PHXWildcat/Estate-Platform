/**
 * THE README'S ROUTE TABLES, DERIVED FROM THE CONTROLLERS (M27 PR1b).
 *
 * `README.md` documents this service's routes in two hand-written tables, and a
 * hand-maintained list beside a thing that grows is this repo's most repeated
 * defect. It had already drifted twice by the time this fence was written: M27
 * PR1b added four item routes and documented none of them, and `GET
 * /v1/vault/recovery-key` — shipped in M14 — had never been in the emergency
 * table at all. Both are the same failure, and neither was visible to any gate,
 * because prose cannot go red.
 *
 * ANCHORED ON WHAT NEST RESOLVES, NOT ON THE SOURCE TEXT. The live set is read
 * from `PATH_METADATA`/`METHOD_METADATA` on the controller prototypes, which is
 * what the router itself consults at request time. A regex over the decorators
 * would be defeated by any spelling it does not recognise, and — as this
 * milestone found the hard way — happily counts a decorator quoted inside a doc
 * comment as a route.
 *
 * SETS, BOTH DIRECTIONS. An undocumented route and a documented route that no
 * longer exists are different defects with different fixes, so they get
 * different assertions rather than one count that can be preserved by a
 * mis-attribution.
 *
 * PARAMETER NAMES ARE NORMALISED (`:policyId` and `:itemId` both become `:id`),
 * because the table documents the SHAPE of a route and the README should not go
 * red over a rename the router does not care about. What is NOT normalised is
 * the method or any literal segment: `items/restorable` and `items/:id` are
 * different routes and this fence must be able to tell them apart — their
 * declaration ORDER is load-bearing.
 */
import 'reflect-metadata';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { EmergencyAccessController } from '../src/emergency.controller';
import { VaultController } from '../src/vault.controller';

/** Both controllers this README documents. Named so the corpus is stated. */
const CONTROLLERS = {
  VaultController,
  EmergencyAccessController,
} as const;

const normalise = (route: string): string => route.replace(/:[A-Za-z][A-Za-z0-9_]*/g, ':id');

function routesOf(controller: { prototype: object }): string[] {
  const prefix = Reflect.getMetadata(PATH_METADATA, controller) as string;
  const out: string[] = [];
  for (const name of Object.getOwnPropertyNames(controller.prototype)) {
    if (name === 'constructor') continue;
    const handler = (controller.prototype as Record<string, unknown>)[name] as object;
    const path = Reflect.getMetadata(PATH_METADATA, handler) as string | undefined;
    const method = Reflect.getMetadata(METHOD_METADATA, handler) as number | undefined;
    if (path === undefined || method === undefined) continue;
    out.push(normalise(`${RequestMethod[method]} /${prefix}/${path}`.replace(/\/{2,}/g, '/')));
  }
  return out;
}

const README = readFileSync(join(__dirname, '..', 'README.md'), 'utf8');

/**
 * Route cells from every table row in the README. A cell may carry bold markers
 * (`deny` is emphasised) and may name several methods for one path
 * (`GET,POST /v1/vault/emergency-access`), so both are expanded here rather
 * than being reasons to reword the document.
 */
function documentedRoutes(): string[] {
  const out: string[] = [];
  for (const match of README.matchAll(/^\|\s*\*{0,2}`([^`]+)`\*{0,2}\s*\|/gm)) {
    const cell = match[1] ?? '';
    const split = cell.indexOf(' ');
    if (split < 0) continue;
    const path = cell.slice(split + 1).trim();
    if (!path.startsWith('/v1/')) continue;
    for (const method of cell.slice(0, split).split(',')) {
      out.push(normalise(`${method.trim()} ${path}`));
    }
  }
  return out;
}

const live = Object.values(CONTROLLERS).flatMap(routesOf).sort();
const documented = documentedRoutes().sort();

describe('the README route tables agree with the controllers (M27 PR1b)', () => {
  // ANTI-VACUITY, AT EVERY LEVEL RATHER THAN ON THE TOTAL. Two empty sets are
  // equal, and a regex that stops matching produces exactly that. Each
  // controller is asserted to contribute separately, because one of them going
  // silent would leave a total that still looks plausible.
  it.each(Object.entries(CONTROLLERS))('%s contributes routes to the live set', (_name, c) => {
    expect(routesOf(c).length).toBeGreaterThan(0);
  });

  it('the README parse found routes from both tables', () => {
    // A case from each table that must match, so a parser that silently starts
    // returning nothing cannot pass as agreement.
    expect(documented).toContain('POST /v1/vault/reset');
    expect(documented).toContain('POST /v1/vault/emergency-access/:id/release');
  });

  it('every live route is documented', () => {
    expect(live.filter((r) => !documented.includes(r))).toEqual([]);
  });

  it('every documented route is live', () => {
    expect(documented.filter((r) => !live.includes(r))).toEqual([]);
  });

  it('no route is listed twice in the README', () => {
    const seen = new Set<string>();
    const dupes = documented.filter((r) => (seen.has(r) ? true : (seen.add(r), false)));
    expect(dupes).toEqual([]);
  });
});
