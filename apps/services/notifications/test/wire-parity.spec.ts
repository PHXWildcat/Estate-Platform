/**
 * THE TWO ENDS OF ONE WIRE, PARSED BY THE THING THAT ACTUALLY PARSES THEM.
 *
 * WHY THIS EXISTS. M17 PR3 shipped a `sendPasswordReset` that emitted
 * `{userId, code}` at a route whose `RecoverySchema` is `.strict()` and
 * requires `kind`. Every reset send answered 400; identity retires a code whose
 * send fails, so the code was minted, mailed nowhere and revoked — a recovery
 * ceremony that could never complete, in the PR whose whole subject it was.
 *
 * TWENTY-SEVEN TESTS PASSED OVER IT, and the reason is the shape rather than
 * the oversight: the body was declared TWICE, and each side's suite validated
 * its own declaration. The client spec asserted method, URL and credential —
 * never the body — and its own fixture used the code `'PR1-ABCD'`, which
 * `RESET_CODE_PATTERN` rejects. The service specs built their payloads by hand,
 * so they only ever exercised bodies somebody had already made valid. Nothing
 * anywhere put one side's OUTPUT into the other side's PARSER. This is the
 * repo's recurring drift class — `GQL_ERROR_CODES` (2026-08-10), the
 * `notification_sends` kind CHECK falling behind the wire enum (M14 PR0) — and
 * the remedy is the same one M14 PR0 adopted: derive the cases, do not list
 * them.
 *
 * WHY IT LIVES HERE. `packages/notifications-client` cannot import the service
 * (wrong direction, and it would create a package edge), while this test tree
 * already imports the client. So the parse happens on the side that owns the
 * schemas, against the client the callers really use.
 *
 * WHAT IT ANCHORS ON. The real `HttpNotificationsClient`, the real exported
 * schemas, and the real controller source. Not a restatement of any of the
 * three: a fence that re-declares the shape it is checking is a third copy.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HttpNotificationsClient, type FetchLike } from '@estate/notifications-client';
import type { z } from 'zod';
import {
  AccountSecuritySchema,
  EmailChangeSchema,
  RecipientSchema,
  RecoverySchema,
  ReplaceSchema,
  SendSchema,
  VerificationSchema,
} from '../src/schemas';

const USER = 'b6c9a1de-0000-4000-8000-000000000001';
/** A real minted-shape reset code — `RESET_CODE_PATTERN` is anchored and strict. */
const RESET_CODE = 'PR1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';
const VERIFY_CODE = 'EV1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';
const CHANGE_CODE = 'EC1-K7MN-2M6Y-1RAZ-3HYH-VB3H-18R7-YX5R-FB3E';

interface Recorded {
  url: string;
  method: string;
  body: unknown;
}

/**
 * Every port method that PUTS A BODY ON THE WIRE, with the schema its route
 * parses that body with.
 *
 * Declared as data with a reason per entry — the credential-graph convention —
 * because "which parser decides whether this call can ever succeed" is exactly
 * the question that went unanswered for a whole PR. `recipientStatus` is absent
 * deliberately: it is a GET carrying no body, so there is nothing to parse, and
 * the coverage assertion below accounts for it explicitly rather than letting
 * an omission look like an oversight.
 */
const WIRE: ReadonlyArray<{
  method: string;
  path: string;
  /** The decorator segment when the path carries a parameter (the request URL
   * holds a real id; the controller declares `:userId`). Defaults to `path`. */
  route?: string;
  schema: z.ZodTypeAny;
  call: (c: HttpNotificationsClient) => Promise<unknown>;
}> = [
  {
    method: 'send',
    path: '/send',
    schema: SendSchema,
    call: (c) => c.send({ userId: USER, kind: 'emergency.requested', channel: 'email' }),
  },
  {
    method: 'upsertRecipient',
    path: '/recipients',
    schema: RecipientSchema,
    call: (c) => c.upsertRecipient({ userId: USER, email: 'owner@example.com' }),
  },
  {
    method: 'sendAddressVerification',
    path: '/verification',
    schema: VerificationSchema,
    // No `kind` — M14's verification wire carries none and the route supplies
    // it, which is the opposite of the choice M17's two routes make. The
    // asymmetry is real and is left alone here: this fence's job is to assert
    // the two ends AGREE, not to make them uniform.
    call: (c) => c.sendAddressVerification({ userId: USER, code: VERIFY_CODE }),
  },
  {
    method: 'sendAccountSecurity',
    path: '/security',
    schema: AccountSecuritySchema,
    call: (c) => c.sendAccountSecurity({ userId: USER, kind: 'identity.password_changed' }),
  },
  {
    method: 'sendPasswordReset',
    path: '/recovery',
    schema: RecoverySchema,
    call: (c) =>
      c.sendPasswordReset({ userId: USER, kind: 'identity.password_reset', code: RESET_CODE }),
  },
  {
    method: 'sendEmailChange',
    path: '/email-change',
    schema: EmailChangeSchema,
    call: (c) =>
      c.sendEmailChange({
        userId: USER,
        kind: 'identity.email_change',
        code: CHANGE_CODE,
        email: 'new-address@example.com',
      }),
  },
  {
    method: 'replaceRecipient',
    path: `/recipients/${USER}/replace`,
    route: '/recipients/:userId/replace',
    schema: ReplaceSchema,
    call: (c) => c.replaceRecipient({ userId: USER, email: 'new-address@example.com' }),
  },
];

function recordingClient(): { client: HttpNotificationsClient; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fetchImpl: FetchLike = (url, init) => {
    calls.push({
      url,
      method: init.method,
      body: init.body === undefined ? undefined : JSON.parse(init.body),
    });
    // Every route on this service answers one of these two shapes; the client
    // only reads them, and this file is about what it SENDS.
    return Promise.resolve({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ delivered: true, channel: 'email', ok: true }),
    });
  };
  return {
    client: new HttpNotificationsClient({
      notificationsUrl: 'http://notifications:3009/',
      credentials: {
        send: 's',
        recipients: 'r',
        verification: 'v',
        status: 't',
        security: 'y',
        recovery: 'c',
        emailChange: 'e',
      },
      fetchImpl,
    }),
    calls,
  };
}

describe('every body the client emits parses with the schema its route uses', () => {
  it.each(WIRE.map((w) => [w.method, w] as const))(
    '%s',
    async (_name, entry: (typeof WIRE)[number]) => {
      const { client, calls } = recordingClient();
      await entry.call(client);

      // Anti-vacuity: a client method that stopped calling the transport would
      // otherwise pass this test by emitting nothing at all.
      expect(calls).toHaveLength(1);
      const call = calls[0] as Recorded;
      expect(call.url).toContain(entry.path);
      expect(call.body).toBeDefined();

      const parsed = entry.schema.safeParse(call.body);
      // Reported as the issue list rather than a bare boolean: when this fails,
      // the whole point is to say WHICH field the two ends disagree about.
      expect({
        method: entry.method,
        ok: parsed.success,
        issues: parsed.success
          ? []
          : parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.code}`),
      }).toEqual({ method: entry.method, ok: true, issues: [] });
    },
  );

  it('the schemas are STRICT — a positive control, so parsing cannot be vacuous', async () => {
    // Every schema above is `.strict()`. If one were widened to passthrough the
    // sweep would keep passing while the property it asserts evaporated, which
    // is the fence-that-stopped-matching shape (2026-08-07).
    //
    // THE OBVIOUS SPELLING OF THIS TEST DOES NOT WORK, and mutation testing is
    // what said so. Parsing `{definitely: 'junk'}` and asserting it fails is
    // satisfied by the REQUIRED-FIELD checks alone, so it passes identically
    // under `.passthrough()` — a control named for strictness that never
    // touched it. Strictness is only observable on a body that is otherwise
    // VALID, so each case takes the real emitted body and adds one unknown key.
    for (const entry of WIRE) {
      const { client, calls } = recordingClient();
      await entry.call(client);
      const valid = (calls[0] as Recorded).body as Record<string, unknown>;

      expect({ method: entry.method, ok: entry.schema.safeParse(valid).success }).toEqual({
        method: entry.method,
        ok: true,
      });
      const smuggled = entry.schema.safeParse({ ...valid, smuggledExtraField: 'x' });
      expect({ method: entry.method, rejectsUnknownKeys: !smuggled.success }).toEqual({
        method: entry.method,
        rejectsUnknownKeys: true,
      });
    }
  });

  it('COVERS every port method that carries a body, derived from the client itself', () => {
    // The direction that catches an ADDED method: a seventh call gets a
    // declaration here or turns this red. Derived from the class prototype
    // rather than from a hand-written list, because a hand-written list is what
    // makes a new method invisible.
    const onPrototype = Object.getOwnPropertyNames(HttpNotificationsClient.prototype).filter(
      (name) => name !== 'constructor' && !name.startsWith('#'),
    );
    // `recipientStatus` and `markRecipientVerified` are the exceptions and are
    // named, not silently subtracted: one is a GET with no body, the other's
    // whole payload is a path parameter.
    const bodyless = ['recipientStatus', 'markRecipientVerified'];
    const covered = new Set(WIRE.map((w) => w.method));
    const uncovered = onPrototype.filter(
      (name) => !covered.has(name) && !bodyless.includes(name) && !name.startsWith('request'),
    );
    expect(uncovered).toEqual([]);
    expect(WIRE.length).toBeGreaterThanOrEqual(5);
  });

  it('every declared path is a route the controller really serves', () => {
    // The other direction: a path renamed in the controller and not here would
    // leave this file parsing bodies against a schema nothing routes to.
    const controller = readFileSync(
      join(__dirname, '..', 'src', 'internal.controller.ts'),
      'utf8',
    ).replace(/\/\*[\s\S]*?\*\//g, '');
    for (const { method, path, route } of WIRE) {
      const segment = (route ?? path).replace(/^\//, '');
      expect({
        method,
        served: new RegExp(`@(?:Post|Put)\\('${segment}'\\)`).test(controller),
      }).toEqual({ method, served: true });
    }
  });
});
