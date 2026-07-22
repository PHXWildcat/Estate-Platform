import { createHash, createHmac } from 'node:crypto';
import { StubPlaidGateway } from '../src/stub-plaid-gateway';
import { WebhookVerifier } from '../src/webhook-verifier';

const BODY = Buffer.from(JSON.stringify({ webhook_code: 'SYNC_UPDATES_AVAILABLE', item_id: 'x' }));

describe('WebhookVerifier (Plaid-Verification JWT, TB5)', () => {
  let gateway: StubPlaidGateway;
  let now: Date;
  let verifier: WebhookVerifier;

  beforeEach(() => {
    gateway = new StubPlaidGateway();
    now = new Date('2026-07-22T12:00:00Z');
    verifier = new WebhookVerifier(gateway, () => now);
  });

  it('accepts a genuine ES256 signature over the exact body', async () => {
    const jwt = gateway.signWebhook(BODY.toString('utf8'), { iatMs: now.getTime() });
    await expect(verifier.verify(jwt, BODY)).resolves.toEqual({ valid: true });
  });

  it('rejects a missing or structurally broken JWT', async () => {
    expect((await verifier.verify(undefined, BODY)).valid).toBe(false);
    expect((await verifier.verify('not-a-jwt', BODY)).valid).toBe(false);
    expect((await verifier.verify('a.b', BODY)).valid).toBe(false);
    expect((await verifier.verify('%%%.%%%.%%%', BODY)).valid).toBe(false);
  });

  it('rejects algorithm confusion: alg none and HS256 both fail on the pinned header', async () => {
    const payload = {
      iat: Math.floor(now.getTime() / 1000),
      request_body_sha256: createHash('sha256').update(BODY).digest('hex'),
    };
    const b64 = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');

    const none = `${b64({ alg: 'none', kid: gateway.webhookKid })}.${b64(payload)}.`;
    expect(await verifier.verify(none, BODY)).toEqual({ valid: false, reason: 'bad_header' });

    // HS256 "signed" with the public JWK as the HMAC key — the classic
    // key-confusion attack; the pinned alg rejects it at the header.
    const signingInput = `${b64({ alg: 'HS256', kid: gateway.webhookKid })}.${b64(payload)}`;
    const mac = createHmac('sha256', 'public-key-bytes').update(signingInput).digest('base64url');
    expect(await verifier.verify(`${signingInput}.${mac}`, BODY)).toEqual({
      valid: false,
      reason: 'bad_header',
    });
  });

  it('rejects an unknown kid', async () => {
    const jwt = gateway.signWebhook(BODY.toString('utf8'), {
      iatMs: now.getTime(),
      kid: 'rotated-away-key',
    });
    expect(await verifier.verify(jwt, BODY)).toEqual({ valid: false, reason: 'unknown_kid' });
  });

  it('rejects a signature from a different key', async () => {
    const impostor = new StubPlaidGateway(); // different keypair, same kid
    const jwt = impostor.signWebhook(BODY.toString('utf8'), { iatMs: now.getTime() });
    expect(await verifier.verify(jwt, BODY)).toEqual({ valid: false, reason: 'bad_signature' });
  });

  it('rejects a stale iat (replay hardening)', async () => {
    const jwt = gateway.signWebhook(BODY.toString('utf8'), {
      iatMs: now.getTime() - 6 * 60 * 1000,
    });
    expect(await verifier.verify(jwt, BODY)).toEqual({ valid: false, reason: 'stale_iat' });
  });

  it('rejects a body that does not match the signed hash', async () => {
    const jwt = gateway.signWebhook(BODY.toString('utf8'), { iatMs: now.getTime() });
    const tampered = Buffer.from(JSON.stringify({ webhook_code: 'ERROR', item_id: 'other' }));
    expect(await verifier.verify(jwt, tampered)).toEqual({
      valid: false,
      reason: 'body_hash_mismatch',
    });
  });

  it('caches verification keys per kid', async () => {
    const spy = jest.spyOn(gateway, 'getWebhookVerificationKey');
    const jwt = gateway.signWebhook(BODY.toString('utf8'), { iatMs: now.getTime() });
    await verifier.verify(jwt, BODY);
    await verifier.verify(jwt, BODY);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
