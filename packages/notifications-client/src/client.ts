import { z } from 'zod';

/** DI token consumers use to inject the client (or a test double). */
export const NOTIFICATIONS = Symbol('NOTIFICATIONS');

/** Header carrying the service credential. Mirrors @estate/auth-guard's
 * constant; duplicated rather than imported so this package keeps a
 * zero-workspace-dependency tree (the settlement-client precedent). */
export const SERVICE_CREDENTIAL_HEADER = 'x-estate-service-credential';

/** Minimal fetch shape so tests inject a transport double (no real network). */
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * ESTATE notifications: the closed set of things a SEND holder can make the
 * platform say. Adding a kind means adding a template in the notifications
 * service — there is deliberately NO free-text field anywhere on this wire, so
 * no caller can put estate content into a carrier message (docs/03 §5.4:
 * emails/SMS are content-free pointers).
 */
export const ESTATE_NOTIFICATION_KINDS = [
  'emergency.requested',
  'emergency.blocked',
  'emergency.reminder',
  'emergency.released',
  'emergency.revoked',
  'vault.reset',
  'vault.grantees_changed',
  'settlement.case_opened',
  'settlement.owner_contact',
  // M13: somebody claimed a link to this owner's estate contact, which is the
  // moment they become able to open a death case against them (docs/03 §6b).
  'contact.link_claimed',
] as const;
export type EstateNotificationKind = (typeof ESTATE_NOTIFICATION_KINDS)[number];

/**
 * SYSTEM notifications: kinds that are NOT reachable through `send`.
 *
 * M14's address verification is the first and only one, and the separation is
 * the control rather than tidiness. Its template needs a CODE, so a caller who
 * could name it on the send route would render a message with `undefined`
 * where the code belongs — a "here is your Estate verification code:
 * undefined" mail, authored by whichever service holds the broadly-held send
 * credential. It travels on its own route, behind its own credential
 * (`NOTIFICATIONS_VERIFY_INTERNAL_TOKEN`, identity alone), with its own typed
 * input; `SendSchema` in the notifications service is built from
 * ESTATE_NOTIFICATION_KINDS so the exclusion is structural, not a comment.
 */
export const SYSTEM_NOTIFICATION_KINDS = [
  'identity.address_verification',
  // M17: the account's own credentials changed. A SYSTEM kind for the reason
  // above turned the other way round — this one carries no variable at all, but
  // it must not be reachable through `send`, because that credential is held by
  // vault, settlement and profile and none of them has any business telling a
  // user their password was changed. It is the one message an attacker would
  // most like to be able to send: it is exactly what a phishing pretext looks
  // like, and a user who receives it acts on it.
  'identity.password_changed',
] as const;
export type SystemNotificationKind = (typeof SYSTEM_NOTIFICATION_KINDS)[number];

/**
 * The ACCOUNT-SECURITY kinds — the subset of system kinds that
 * `NOTIFICATIONS_SECURITY_INTERNAL_TOKEN` opens (M17).
 *
 * A subset rather than "all system kinds", and the distinction is the whole
 * reason this is a separate edge: `identity.address_verification` needs a code
 * and travels on the VERIFY credential, while these say something happened to
 * the account and carry nothing. A holder of one must not inherit the other —
 * the M14 reasoning that split VERIFY from RECIPIENTS, applied before the
 * second holder exists rather than after.
 */
export const ACCOUNT_SECURITY_KINDS = ['identity.password_changed'] as const;
export type AccountSecurityKind = (typeof ACCOUNT_SECURITY_KINDS)[number];

/**
 * Every kind the platform can log a send for. This is the vocabulary of
 * `notification_sends.kind` — its DDL CHECK is derived from this list and an
 * int spec drives every member, because M13 added a kind here and not there and
 * the mismatch mailed owners while telling their audit trail it had not.
 */
export const NOTIFICATION_KINDS = [
  ...ESTATE_NOTIFICATION_KINDS,
  ...SYSTEM_NOTIFICATION_KINDS,
] as const;
export type NotificationKind = (typeof NOTIFICATION_KINDS)[number];

/**
 * The channel the CALLER asked for (settlement's contact sweep cycles these).
 * Delivery this milestone is email-only: the service substitutes and reports
 * the channel it actually used, and the caller records that truth.
 */
export const NOTIFICATION_CHANNELS = ['email', 'push', 'sms', 'voice'] as const;
export type NotificationChannel = (typeof NOTIFICATION_CHANNELS)[number];

export interface NotificationSendInput {
  /** The recipient, as a user id. Address resolution happens inside the
   * notifications service against its own encrypted recipient store — no
   * caller ever handles an address. */
  userId: string;
  kind: EstateNotificationKind;
  channel?: NotificationChannel;
  /** Deadline the notification may state (waiting-period end). The one piece
   * of variable data an ESTATE template may carry, per the M6/M7 port
   * contracts. */
  deadline?: Date;
}

/**
 * The address-verification send (M14). Its own input type, its own route and
 * its own credential — see SYSTEM_NOTIFICATION_KINDS.
 *
 * `code` is the SECOND piece of variable data the platform has ever put in a
 * carrier message, and the first that is not a date. That is an approved
 * deviation from M9's content doctrine, recorded in docs/03 §6c: it is
 * PLATFORM-AUTHORED (minted by identity from `randomBytes`, never derived from
 * anything the user wrote), it is opaque, it carries no estate fact, and it is
 * single-use and short-lived. It is a `code` and never a `text` field
 * precisely so the doctrine's real property survives — no caller has anywhere
 * to put prose. "We never link you" is also untouched: the template states the
 * code and tells the reader to type it into the app.
 */
export interface AddressVerificationInput {
  userId: string;
  code: string;
}

/**
 * An account-security notice (M17). A user id and a CLOSED kind — no text, no
 * code, no timestamp, no deadline.
 *
 * The absence of a date field is deliberate and slightly awkward: "your
 * password was changed" would read better with a time in it, and the moment
 * this wire carries one it carries a variable a caller chooses. The message
 * says to sign in and check, which is what a recipient should do anyway and
 * cannot be faked into a plausible-looking lie.
 */
export interface AccountSecurityInput {
  userId: string;
  kind: AccountSecurityKind;
}

/**
 * The exact shape a verification code may take ON THE WIRE.
 *
 * IT LIVES HERE, in the wire contract both services import, because the M14
 * review found the two ends disagreeing: notifications validated
 * `/^[0-9A-Z-]+$/` with a 64-character cap while identity mints Crockford
 * base32 (no I, L, O or U), so the route accepted 64 characters of readable
 * uppercase English and `renderAddressVerification` interpolated it verbatim
 * into a real message from the platform's verified sender. A free-text field
 * by another name, in the one wire the content doctrine exists to keep
 * text-free.
 *
 * The obvious fix — tighten notifications' regex — was rejected on identity's
 * own stated reasoning that a second pattern "would only add a second place
 * for the alphabet to drift". One shared declaration is the version of that
 * fix without the drift: notifications validates against it, and identity has
 * a spec asserting every code it mints satisfies it, so a change to either end
 * fails a test instead of silently widening what may be mailed.
 *
 * NOTIFICATIONS MUST STILL VALIDATE IT ITSELF. The doctrine is a property of
 * the delivery boundary, and the credential model is that a bearer of a secret
 * IS the service — so "identity would never send prose" is not something the
 * notifications service may assume about its caller.
 */
export const VERIFICATION_CODE_PATTERN = /^EV1(-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{4}){8}$/;

/**
 * What the delivery store knows about reaching a user.
 *
 * `verified` answers the question three shipped fail-closed gates have always
 * ASSUMED and never asked: not "is a carrier wired" (that is
 * `deliversToRealChannels`, a property of the adapter that cannot be wrong
 * about a recipient because it never looks at one), but "did the person who
 * owns this account prove they receive mail at the address we would use".
 */
export interface RecipientStatus {
  readonly verified: boolean;
}

/**
 * What happened to a send. `accepted: false` means the request never reached a
 * healthy notifications service (unwired credential, network failure, non-2xx,
 * contract drift); `delivered: false` means the service answered but could not
 * deliver (no recipient on record, carrier refusal). Callers record either as
 * a non-delivery — this client NEVER throws, because a notification failure
 * must not roll back the state change it describes (the M6 design).
 */
export type SendOutcome =
  | {
      accepted: true;
      delivered: boolean;
      channel: string;
      /**
       * Whether the address this was sent to had been PROVED by the user (M14).
       *
       * It rides the send response so a caller that proceeds on an unverified
       * recipient can record that fact on its own audit trail without holding
       * the status credential — settlement is the case that matters: its §5.1
       * gates proceed and record, so it must never need to ask the question
       * separately.
       *
       * `false` also covers "the service could not tell", which is the safe
       * reading: a caller records that it could not confirm reach, never that
       * it could.
       */
      recipientVerified: boolean;
    }
  | { accepted: false };

export interface NotificationsPort {
  send(input: NotificationSendInput): Promise<SendOutcome>;
  /** Registers/refreshes the user's delivery address. Identity calls this at
   * registration and login — the two moments the user themselves supplies the
   * plaintext email — so no service ever needs a ciphertext read path. */
  upsertRecipient(input: { userId: string; email: string }): Promise<{ ok: boolean }>;
  /** Mail one address-verification code. Identity alone; its own credential. */
  sendAddressVerification(input: AddressVerificationInput): Promise<SendOutcome>;
  /**
   * Tell a user something changed about their ACCOUNT's credentials (M17).
   * Identity alone, on its own credential — not the estate send one, which
   * vault, settlement and profile hold.
   *
   * The input carries a user id and a CLOSED kind and nothing else: there is no
   * field for text, no field for a code, and no field for a timestamp, so a
   * holder chooses which of a closed set of platform-authored notices fires and
   * nothing about what it says.
   */
  sendAccountSecurity(input: AccountSecurityInput): Promise<SendOutcome>;
  /** Record that the user proved ownership of the stored address. Identity
   * alone, on the SAME credential as `upsertRecipient` — vouching for an
   * address and setting one are the same capability class (M14 decision 5). */
  markRecipientVerified(input: { userId: string }): Promise<{ ok: boolean }>;
  /**
   * Ask the delivery store whether it can reach a user provably.
   *
   * `null` means UNANSWERABLE — no credential, network failure, non-2xx,
   * contract drift — and is deliberately NOT collapsed into
   * `{verified: false}`. This is the first network round trip the M6/M7/M13
   * notification gates have ever made, so before M14 the check could not fail
   * and no call site had an error path for it. Making the two outcomes
   * distinct forces each caller to write down what an outage means for its own
   * gate rather than letting a thrown exception decide; the arming gates
   * treat both as "refuse", which is a decision they state rather than inherit.
   */
  recipientStatus(userId: string): Promise<RecipientStatus | null>;
}

const SendResponseSchema = z.object({
  delivered: z.boolean(),
  channel: z.string().min(1),
  // M14. `.default(false)` rather than required, so a client talking to a
  // notifications service that predates the field degrades to "could not
  // confirm" instead of narrowing the whole send to contract drift. The safe
  // direction: a caller records that it could not confirm reach, never that it
  // could.
  recipientVerified: z.boolean().default(false),
});

const UpsertResponseSchema = z.object({ ok: z.literal(true) });

const StatusResponseSchema = z.object({ verified: z.boolean() });

/**
 * The credentials a caller holds, ONE PER EDGE.
 *
 * Four now, and each field is a separate capability the credential graph
 * grants separately — no service holds all four, and every field is optional
 * because an absent credential is the normal state for a service that does not
 * hold that edge. A method whose credential is missing short-circuits to its
 * failure outcome WITHOUT a round trip, so an over-broad client is a
 * configuration that cannot reach the route rather than one that reaches it
 * and is rejected.
 *
 * They are separate fields and not one string because that single string is
 * precisely what the M9 security review found: send and recipient-upsert
 * shared one secret, so vault's copy could repoint any owner's address.
 */
export interface NotificationsCredentials {
  /** NOTIFICATIONS_INTERNAL_TOKEN — fire an estate template kind. */
  send?: string;
  /** NOTIFICATIONS_RECIPIENTS_INTERNAL_TOKEN — set the address, vouch for it. */
  recipients?: string;
  /** NOTIFICATIONS_VERIFY_INTERNAL_TOKEN — mail one verification code. */
  verification?: string;
  /** NOTIFICATIONS_STATUS_INTERNAL_TOKEN — read the verified bit. */
  status?: string;
  /** NOTIFICATIONS_SECURITY_INTERNAL_TOKEN — mail one account-security notice. */
  security?: string;
}

export interface HttpNotificationsClientOptions {
  /** Base URL of the notifications service (e.g. http://notifications:3008). */
  notificationsUrl: string;
  credentials?: NotificationsCredentials;
  fetchImpl?: FetchLike;
}

const NOT_ACCEPTED: SendOutcome = { accepted: false };

/**
 * HTTP implementation against the notifications service's internal routes.
 * Every failure narrows to an outcome, never an exception: senders (vault,
 * settlement) treat notification delivery as best-effort-and-recorded, and
 * identity's recipient upsert is best-effort by design (a notifications
 * outage must not block registration or login).
 */
export class HttpNotificationsClient implements NotificationsPort {
  private readonly notificationsUrl: string;
  private readonly credentials: NotificationsCredentials;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpNotificationsClientOptions) {
    this.notificationsUrl = options.notificationsUrl.replace(/\/$/, '');
    this.credentials = options.credentials ?? {};
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  /** Request + parse, or null on ANY failure — including an unheld credential. */
  private async requestJson(
    credential: string | undefined,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    if (!credential) {
      // No round trip: a service that does not hold this edge must not even
      // announce itself to the route (and a blank header would be rejected
      // anyway — the guard fails closed on '').
      return null;
    }
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.notificationsUrl}${path}`, {
        method,
        headers: {
          'content-type': 'application/json',
          [SERVICE_CREDENTIAL_HEADER]: credential,
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      return null; // network/DNS failure ⇒ the outcome, not an exception
    }
    if (!response.ok) {
      return null;
    }
    try {
      return await response.json();
    } catch {
      return null;
    }
  }

  private static outcomeOf(body: unknown): SendOutcome {
    const parsed = SendResponseSchema.safeParse(body);
    if (!parsed.success) {
      return NOT_ACCEPTED; // contract drift ⇒ recorded as not sent, never guessed
    }
    return {
      accepted: true,
      delivered: parsed.data.delivered,
      channel: parsed.data.channel,
      recipientVerified: parsed.data.recipientVerified,
    };
  }

  async send(input: NotificationSendInput): Promise<SendOutcome> {
    const payload = {
      userId: input.userId,
      kind: input.kind,
      channel: input.channel ?? 'email',
      ...(input.deadline !== undefined ? { deadline: input.deadline.toISOString() } : {}),
    };
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.send,
        'POST',
        '/internal/v1/notifications/send',
        payload,
      ),
    );
  }

  async upsertRecipient(input: { userId: string; email: string }): Promise<{ ok: boolean }> {
    const body = await this.requestJson(
      this.credentials.recipients,
      'PUT',
      '/internal/v1/notifications/recipients',
      { userId: input.userId, email: input.email },
    );
    return { ok: UpsertResponseSchema.safeParse(body).success };
  }

  async markRecipientVerified(input: { userId: string }): Promise<{ ok: boolean }> {
    const body = await this.requestJson(
      this.credentials.recipients,
      'PUT',
      `/internal/v1/notifications/recipients/${encodeURIComponent(input.userId)}/verified`,
      {},
    );
    return { ok: UpsertResponseSchema.safeParse(body).success };
  }

  async sendAddressVerification(input: AddressVerificationInput): Promise<SendOutcome> {
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.verification,
        'POST',
        '/internal/v1/notifications/verification',
        { userId: input.userId, code: input.code },
      ),
    );
  }

  async sendAccountSecurity(input: AccountSecurityInput): Promise<SendOutcome> {
    return HttpNotificationsClient.outcomeOf(
      await this.requestJson(
        this.credentials.security,
        'POST',
        '/internal/v1/notifications/security',
        {
          userId: input.userId,
          kind: input.kind,
        },
      ),
    );
  }

  async recipientStatus(userId: string): Promise<RecipientStatus | null> {
    const body = await this.requestJson(
      this.credentials.status,
      'GET',
      `/internal/v1/notifications/recipients/${encodeURIComponent(userId)}/status`,
    );
    const parsed = StatusResponseSchema.safeParse(body);
    // null, not `{verified:false}`: see NotificationsPort.recipientStatus. An
    // unanswerable query and a real "not verified" are different facts, and the
    // callers decide separately what each means for their own gate.
    return parsed.success ? { verified: parsed.data.verified } : null;
  }
}
