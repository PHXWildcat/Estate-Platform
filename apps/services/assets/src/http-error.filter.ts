import { Catch, HttpException, type ArgumentsHost, type ExceptionFilter } from '@nestjs/common';

/** Minimal structural view of the express response (avoids @types/express). */
interface MinimalResponse {
  status(code: number): { json(body: unknown): void };
}

/**
 * Generic error boundary. Whatever explodes inside a handler, the client sees
 * only a stable machine-readable error token — never exception messages,
 * stack traces, SQL, or anything that could carry PII (CLAUDE.md: no PII in
 * any log or error message). Intentionally, nothing is logged here either;
 * observability comes from audit events, which are PII-free by construction.
 */
@Catch()
export class HttpErrorFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<MinimalResponse>();
    if (exception instanceof HttpException) {
      const body = exception.getResponse();
      const errorToken =
        typeof body === 'object' && body !== null && 'error' in body
          ? body.error
          : 'request_failed';
      response
        .status(exception.getStatus())
        .json({ error: typeof errorToken === 'string' ? errorToken : 'request_failed' });
      return;
    }
    response.status(500).json({ error: 'internal_error' });
  }
}
