/**
 * WHICH VAULT ROUTES A BROWSER EXTENSION MAY REACH — enforced (M16).
 *
 * `AUDIENCE_ROUTE_ADMITTERS` in @estate/auth-guard is the declaration, and that
 * package's own fence already scans this service's SOURCE for stray decorators.
 * This suite is the other half, and it earns its place twice over:
 *
 *   · it reads the DECORATED METADATA off the real controller prototypes, which
 *     is what Nest actually resolves at request time — a source scan can be
 *     defeated by a decorator applied any way a regex does not recognise;
 *   · and it NAMES the routes that must never admit the extension, one at a
 *     time. The sweep below would catch a regression either way, but a test that
 *     fails saying `reset` should not admit an extension session tells the next
 *     person WHY, which a diff of a data table does not. Identity's
 *     `mintHandoff` case is the precedent.
 *
 * WHAT AN EXTENSION SESSION IS. It is minted by the M16 pairing ceremony, it
 * carries a long-lived refresh token, and it lives on an artifact delivered by a
 * vendor store that can auto-update it with no CSP in the path. So the question
 * this file answers is not "is the extension trusted" but "what does a
 * compromised one reach", and the answer has to stay: discover, unlock, list
 * ciphertext, lock. Nothing that destroys, nothing that grants, nothing that
 * starts a §5.2 clock.
 */
import 'reflect-metadata';
import { SESSION_AUDIENCE_METADATA } from '@estate/auth-guard';
import { EmergencyAccessController } from '../src/emergency.controller';
import { VaultController } from '../src/vault.controller';

/** Every handler on a controller prototype, minus the constructor. */
function routeNames(controller: { prototype: object }): string[] {
  return Object.getOwnPropertyNames(controller.prototype)
    .filter((name) => name !== 'constructor')
    .sort();
}

function admittedAudiences(
  controller: { prototype: object },
  route: string,
): readonly string[] | undefined {
  const handler = (controller.prototype as unknown as Record<string, object | undefined>)[route];
  // A name that does not exist must not read as "declares no audiences" — the
  // same answer a genuinely undecorated handler gives. Callers check existence
  // separately; this only has to not lie.
  if (handler === undefined) {
    return undefined;
  }
  return Reflect.getMetadata(SESSION_AUDIENCE_METADATA, handler) as readonly string[] | undefined;
}

/**
 * The SEVEN, and the whole of what a paired extension can do at this service.
 *
 * It was five until M16 PR4a, which admitted `createItem` and `updateItem` —
 * the writes PR1 deliberately left for PR4 to decide rather than deciding by
 * omission. Both sit behind `VaultSessionGuard`, so they belong to an UNLOCKED
 * vault and not to the credential: a stolen extension session still cannot
 * reach them without the vault password, the device Secret Key and a fresh
 * step-up.
 *
 * `deleteItem` is NOT here and is asserted below to be refused. It is the
 * destructive verb, it carries `StepUpGuard` as well, and an overwrite is not
 * equivalent to it — `vault_items_versions` captures BEFORE UPDATE OR DELETE,
 * so a write through this audience is recoverable.
 */
const EXTENSION_ROUTES = [
  'keysetStatus',
  'startUnlock',
  'finishUnlock',
  'listItems',
  'createItem',
  'updateItem',
  'lock',
];

/**
 * Named refusals, with the reason each one matters. Not the complete refused
 * set — that is derived below and asserted to be everything else — but the
 * subset where a mistaken grant is worst.
 */
const MUST_REFUSE: ReadonlyArray<{
  controller: { prototype: object };
  route: string;
  why: string;
}> = [
  { controller: VaultController, route: 'reset', why: 'crypto-shreds the vault on step-up alone' },
  { controller: VaultController, route: 'createKeyset', why: 'enrolls key material' },
  { controller: VaultController, route: 'replaceKeyset', why: 'replaces key material' },
  {
    controller: VaultController,
    route: 'deleteItem',
    why: 'destroys an item — the line PR4a did NOT cross when it admitted create and update',
  },
  { controller: VaultController, route: 'getItem', why: 'listItems already returns the blob' },
  {
    controller: EmergencyAccessController,
    route: 'configure',
    why: 'arms the §5.2 escrow',
  },
  {
    controller: EmergencyAccessController,
    route: 'request',
    why: 'starts the §5.2 waiting period',
  },
  {
    controller: EmergencyAccessController,
    route: 'release',
    why: 'the one moment the platform half of a recovery key leaves this service',
  },
  {
    controller: EmergencyAccessController,
    route: 'revoke',
    why: 'tears down an arrangement the owner made',
  },
  { controller: EmergencyAccessController, route: 'rearm', why: 're-arms after a denial' },
  {
    controller: EmergencyAccessController,
    route: 'publishRecoveryKey',
    why: 'publishes the key shares are sealed to',
  },
  {
    controller: EmergencyAccessController,
    route: 'ownRecoveryKey',
    why: 'serves the wrapped private half',
  },
];

describe('vault route audiences match the declaration', () => {
  it('finds the routes it is meant to be checking', () => {
    // Anti-vacuity. A prototype scan that returns nothing would make every
    // assertion below pass — the credential-graph anti-drop lesson.
    const vault = routeNames(VaultController);
    const emergency = routeNames(EmergencyAccessController);
    expect(vault.length).toBe(12);
    expect(emergency.length).toBe(11);
    // 23, not the 22 the decision log cited from M15 — `ownRecoveryKey` arrived
    // in PR3 and the remembered number never caught up. Asserted so the next
    // person counts rather than remembers.
    expect(vault.length + emergency.length).toBe(23);
  });

  it('exactly seven handlers admit an extension session', () => {
    const admitting = routeNames(VaultController).filter((route) =>
      admittedAudiences(VaultController, route)?.includes('extension'),
    );
    expect(admitting.sort()).toEqual([...EXTENSION_ROUTES].sort());
  });

  it('no emergency-access route admits any non-account audience', () => {
    // The whole controller, swept rather than enumerated: emergency access is
    // where a mistaken grant costs the most, and every one of its routes is
    // reachable with CallerGuard alone — five of them with no second guard at
    // all — so an audience widening here needs no other mistake to be exploited.
    for (const route of routeNames(EmergencyAccessController)) {
      expect({ route, admits: admittedAudiences(EmergencyAccessController, route) }).toEqual({
        route,
        admits: undefined,
      });
    }
  });

  it.each(MUST_REFUSE)(
    '$route must never admit an extension session — $why',
    ({ controller, route }) => {
      expect(routeNames(controller)).toContain(route);
      expect(admittedAudiences(controller, route) ?? []).not.toContain('extension');
    },
  );

  it('every route that is not one of the seven refuses the extension', () => {
    // The derived half, so the named list above cannot go stale into a false
    // sense of coverage: a 24th route added tomorrow is refused by default and
    // this notices if it is not.
    //
    // SIXTEEN, down from eighteen when PR4a admitted `createItem` and
    // `updateItem`. The number is asserted rather than computed from
    // EXTENSION_ROUTES on purpose: deriving it from the admitted list would make
    // this test agree with any widening automatically, which is the one thing it
    // exists to refuse. Moving it is meant to cost a deliberate edit.
    const refused = [
      ...routeNames(VaultController).map((route) => ({ c: VaultController, route })),
      ...routeNames(EmergencyAccessController).map((route) => ({
        c: EmergencyAccessController,
        route,
      })),
    ].filter(({ route }) => !EXTENSION_ROUTES.includes(route));
    expect(refused).toHaveLength(16);
    for (const { c, route } of refused) {
      expect({
        route,
        admits: admittedAudiences(c, route)?.includes('extension') ?? false,
      }).toEqual({ route, admits: false });
    }
  });

  it('the five admit account and extension, and NOT a bare extension grant', () => {
    // `AllowSessionAudiences` always prepends the default, and that is what
    // stops a route-level grant from NARROWING: without `account` in the list a
    // decorated route would be reachable from the extension and nowhere else,
    // which reads as a widening and behaves as an outage for ordinary callers.
    for (const route of EXTENSION_ROUTES) {
      expect(admittedAudiences(VaultController, route)).toEqual(['account', 'extension']);
    }
  });
});
