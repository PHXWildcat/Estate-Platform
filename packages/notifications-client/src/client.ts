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
 * The closed set of things the platform can say. Adding a kind means adding a
 * template in the notifications service — there is deliberately NO free-text
 * field anywhere on this wire, so no caller can put estate content into a
 * carrier message (docs/03 §5.4: emails/SMS are content-free pointers).
 */
export const NOTIFICATION_KINDS = [
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
  kind: NotificationKind;
  channel?: NotificationChannel;
  /** Deadline the notification may state (waiting-period end). The one piece
   * of variable data a template may carry, per the M6/M7 port contracts. */
  deadline?: Date;
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
  { accepted: true; delivered: boolean; channel: string } | { accepted: false };

export interface NotificationsPort {
  send(input: NotificationSendInput): Promise<SendOutcome>;
  /** Registers/refreshes the user's delivery address. Identity calls this at
   * registration and login — the two moments the user themselves supplies the
   * plaintext email — so no service ever needs a ciphertext read path. */
  upsertRecipient(input: { userId: string; email: string }): Promise<{ ok: boolean }>;
}

const SendResponseSchema = z.object({
  delivered: z.boolean(),
  channel: z.string().min(1),
});

const UpsertResponseSchema = z.object({ ok: z.literal(true) });

export interface HttpNotificationsClientOptions {
  /** Base URL of the notifications service (e.g. http://notifications:3009). */
  notificationsUrl: string;
  /** Shared service credential. Absent ⇒ every call short-circuits to its
   * failure outcome without a round trip: nothing was sent, and the caller's
   * bookkeeping records exactly that. */
  serviceCredential?: string;
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
  private readonly serviceCredential: string;
  private readonly fetchImpl: FetchLike;

  constructor(options: HttpNotificationsClientOptions) {
    this.notificationsUrl = options.notificationsUrl.replace(/\/$/, '');
    this.serviceCredential = options.serviceCredential ?? '';
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init));
  }

  /** POST/PUT + parse, or null on ANY failure. */
  private async requestJson(method: string, path: string, body: unknown): Promise<unknown> {
    let response: Awaited<ReturnType<FetchLike>>;
    try {
      response = await this.fetchImpl(`${this.notificationsUrl}${path}`, {
        method,
        headers: {
          'content-type': 'application/json',
          [SERVICE_CREDENTIAL_HEADER]: this.serviceCredential,
        },
        body: JSON.stringify(body),
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

  async send(input: NotificationSendInput): Promise<SendOutcome> {
    if (!this.serviceCredential) {
      return NOT_ACCEPTED;
    }
    const payload = {
      userId: input.userId,
      kind: input.kind,
      channel: input.channel ?? 'email',
      ...(input.deadline !== undefined ? { deadline: input.deadline.toISOString() } : {}),
    };
    const body = await this.requestJson('POST', '/internal/v1/notifications/send', payload);
    const parsed = SendResponseSchema.safeParse(body);
    if (!parsed.success) {
      return NOT_ACCEPTED; // contract drift ⇒ recorded as not sent, never guessed
    }
    return { accepted: true, delivered: parsed.data.delivered, channel: parsed.data.channel };
  }

  async upsertRecipient(input: { userId: string; email: string }): Promise<{ ok: boolean }> {
    if (!this.serviceCredential) {
      return { ok: false };
    }
    const body = await this.requestJson('PUT', '/internal/v1/notifications/recipients', {
      userId: input.userId,
      email: input.email,
    });
    return { ok: UpsertResponseSchema.safeParse(body).success };
  }
}
