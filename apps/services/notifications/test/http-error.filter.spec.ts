import { BadRequestException, HttpException, type ArgumentsHost } from '@nestjs/common';
import { HttpErrorFilter } from '../src/http-error.filter';

/**
 * The error boundary is a PII control in THIS service: an error path that
 * echoed an exception message could carry the one secret the service keeps
 * (a recipient address). Pinned directly rather than inferred from the int
 * suite, which drives the service class and never crosses the filter.
 */
describe('HttpErrorFilter', () => {
  const capture = (): {
    host: ArgumentsHost;
    sent: { status?: number; body?: unknown };
  } => {
    const sent: { status?: number; body?: unknown } = {};
    const response = {
      status: (code: number) => {
        sent.status = code;
        return {
          json: (body: unknown) => {
            sent.body = body;
          },
        };
      },
    };
    const host = {
      switchToHttp: () => ({ getResponse: () => response }),
    } as unknown as ArgumentsHost;
    return { host, sent };
  };

  it('passes through a machine-readable error token from an HttpException', () => {
    const { host, sent } = capture();
    new HttpErrorFilter().catch(new BadRequestException({ error: 'invalid_request' }), host);
    expect(sent.status).toBe(400);
    expect(sent.body).toEqual({ error: 'invalid_request' });
  });

  it('replaces a token-less HttpException body with request_failed', () => {
    const { host, sent } = capture();
    new HttpErrorFilter().catch(new HttpException('anything-goes-here', 418), host);
    expect(sent.status).toBe(418);
    expect(sent.body).toEqual({ error: 'request_failed' });
  });

  it('replaces a non-string error token with request_failed', () => {
    const { host, sent } = capture();
    new HttpErrorFilter().catch(new HttpException({ error: { nested: true } }, 409), host);
    expect(sent.status).toBe(409);
    expect(sent.body).toEqual({ error: 'request_failed' });
  });

  it('maps anything else to a bare 500 that never carries the exception text', () => {
    const { host, sent } = capture();
    new HttpErrorFilter().catch(new Error('SES said: mailbox owner@example.com rejected'), host);
    expect(sent.status).toBe(500);
    expect(sent.body).toEqual({ error: 'internal_error' });
    expect(JSON.stringify(sent.body)).not.toContain('example.com');
  });
});
