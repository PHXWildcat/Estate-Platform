import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';

/**
 * The carrier port. Implementations may throw — the service catches and
 * records 'carrier_failure'; a carrier outage is an outcome, never a 500.
 */
export interface EmailSender {
  /** Names the transport in send records ('stub' | 'ses'). */
  readonly transport: string;
  /** True only when messages actually leave the platform. The stub is false —
   * this is the bit callers' capability gates ultimately rest on. */
  readonly deliversToRealChannels: boolean;
  send(input: {
    to: string;
    subject: string;
    body: string;
  }): Promise<{ providerMessageId: string | null }>;
}

/** Dev/test carrier: records instead of delivering. */
export class StubEmailSender implements EmailSender {
  readonly transport = 'stub';
  readonly deliversToRealChannels = false;
  readonly sent: Array<{ to: string; subject: string; body: string }> = [];

  send(input: { to: string; subject: string; body: string }): Promise<{
    providerMessageId: string | null;
  }> {
    this.sent.push(input);
    return Promise.resolve({ providerMessageId: `stub-${this.sent.length}` });
  }
}

/**
 * SES v1 SendEmail — the API LocalStack Community also implements, so the
 * local stack exercises the REAL adapter and the e2e reads the message back
 * through LocalStack's /_aws/ses endpoint. Text body only: an HTML mail with
 * exactly one sentence in it buys nothing but a bigger phishing-lookalike
 * surface.
 */
export class SesEmailSender implements EmailSender {
  readonly transport = 'ses';
  readonly deliversToRealChannels = true;

  constructor(
    private readonly client: SESClient,
    private readonly fromAddress: string,
  ) {}

  async send(input: { to: string; subject: string; body: string }): Promise<{
    providerMessageId: string | null;
  }> {
    const result = await this.client.send(
      new SendEmailCommand({
        Source: this.fromAddress,
        Destination: { ToAddresses: [input.to] },
        Message: {
          Subject: { Data: input.subject, Charset: 'UTF-8' },
          Body: { Text: { Data: input.body, Charset: 'UTF-8' } },
        },
      }),
    );
    return { providerMessageId: result.MessageId ?? null };
  }
}
