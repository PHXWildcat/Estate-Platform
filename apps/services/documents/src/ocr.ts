import { DetectDocumentTextCommand, type TextractClient } from '@aws-sdk/client-textract';
import { z } from 'zod';

/**
 * The OCR port (docs/01 §2.4/§2.6: "OCR ingestion for uploads"). Stub for
 * dev/test, AWS Textract for production, behind one interface.
 *
 * THREAT-MODEL FRAMING (docs/03 TB5, risk #6): OCR output is derived from an
 * untrusted upload and is itself UNTRUSTED DATA. It is only ever (a) sealed
 * into an encrypted artifact under the document's DEK and (b) reduced to
 * HMAC search tokens. It is never parsed for meaning, never logged, never
 * treated as instructions — here or in any downstream consumer.
 *
 * OCR failure is NON-FATAL to an upload (the document stores un-indexed);
 * malware scanning is the fail-closed gate, not this.
 */
export interface OcrEngine {
  /** Extract plain text; empty string means "nothing legible". */
  extractText(content: Buffer, mime: string): Promise<string>;
}

/** Bound the artifact/tokenizer input however noisy the engine output is. */
export const OCR_TEXT_MAX_CHARS = 500_000;

/**
 * Deterministic dev/test OCR: extracts printable-ASCII runs from the raw
 * bytes. That is meaningless for real scans but exactly right for test
 * fixtures, which embed their expected text as literal bytes. NEVER runs in
 * production (config-enforced).
 */
export class StubOcr implements OcrEngine {
  extractText(content: Buffer): Promise<string> {
    const runs = content.toString('latin1').match(/[\x20-\x7E]{4,}/g);
    const text = (runs ?? []).join(' ').slice(0, OCR_TEXT_MAX_CHARS);
    return Promise.resolve(text);
  }
}

/**
 * AWS Textract adapter (synchronous DetectDocumentText — the single-page
 * sync API; multi-page/async Textract jobs are a scale follow-up tracked in
 * docs/04). The client is injected so unit tests exercise the mapping
 * against a stubbed transport (the kms-aws / S3ObjectStore pattern).
 */
export class TextractOcr implements OcrEngine {
  constructor(private readonly client: Pick<TextractClient, 'send'>) {}

  async extractText(content: Buffer): Promise<string> {
    const response = await this.client.send(
      new DetectDocumentTextCommand({ Document: { Bytes: content } }),
    );
    const lines = (response.Blocks ?? [])
      .filter((b) => b.BlockType === 'LINE' && typeof b.Text === 'string')
      .map((b) => b.Text as string);
    return lines.join('\n').slice(0, OCR_TEXT_MAX_CHARS);
  }
}

/** Hard deadline for a sidecar round trip. OCR is best-effort; a slow engine
 *  must degrade the upload to un-indexed, never hold the request open. */
export const OCR_TIMEOUT_MS = 30_000;

/**
 * Cap on the bytes we will buffer from the sidecar. The engine is a separate
 * process on the network, so the M4-review lesson from the clamd client
 * applies unchanged: a peer that dribbles bytes without ever finishing must
 * not be able to grow this process's memory without bound.
 */
export const OCR_RESPONSE_MAX_BYTES = 4 * 1024 * 1024;

/** The sidecar's response envelope. Validated before use — a separate process
 *  is a third party, and its payloads are untrusted input like any other. */
const TesseractResponse = z.object({ text: z.string() });

/** Minimal fetch shape so tests inject a double without network access. */
export type OcrFetch = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body: Uint8Array;
    signal: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  body: {
    getReader(): { read(): Promise<{ done: boolean; value?: Uint8Array | undefined }> };
  } | null;
}>;

export class OcrEngineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OcrEngineError';
  }
}

export interface TesseractOptions {
  /** Base URL of the OCR sidecar. */
  endpoint: string;
  timeoutMs?: number;
}

/**
 * Tesseract adapter, spoken over a minimal HTTP protocol to a sidecar:
 * `POST {endpoint}/ocr` with the raw bytes and their sniffed mime, answering
 * `{"text": "..."}`.
 *
 * The engine runs in its own container rather than in this process, which is
 * the same call the repo has made three times before (clamd on node:net, the
 * Plaid webhook verifier on node:crypto, the in-repo template renderer): the
 * code that touches attacker-supplied bytes gets no new dependency tree. Here
 * the input is a file an attacker uploaded and the parser is a large C++
 * codebase, so keeping it behind a process boundary is the whole point.
 *
 * Everything the sidecar returns is UNTRUSTED DATA and is treated exactly as
 * Textract's output is: sealed under the document's DEK and reduced to HMAC
 * tokens, never parsed for meaning, never logged, never an instruction.
 */
export class TesseractOcr implements OcrEngine {
  private readonly url: string;
  private readonly timeoutMs: number;

  constructor(
    options: TesseractOptions,
    private readonly fetchImpl: OcrFetch = (url, init) => fetch(url, init),
  ) {
    // Strip every trailing slash, not just one: `http://ocr:8884//ocr` is a
    // different path to most routers, and this value comes from an env file.
    this.url = `${options.endpoint.replace(/\/+$/, '')}/ocr`;
    this.timeoutMs = options.timeoutMs ?? OCR_TIMEOUT_MS;
  }

  async extractText(content: Buffer, mime: string): Promise<string> {
    const response = await this.fetchImpl(this.url, {
      method: 'POST',
      headers: { 'content-type': mime, accept: 'application/json' },
      body: content,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      // Status only — a sidecar error body is untrusted text and must never
      // reach a log or an error message.
      throw new OcrEngineError(`ocr sidecar returned status ${response.status}`);
    }
    const raw = await this.readCapped(response.body);
    // JSON.parse's SyntaxError quotes the offending input, which would put
    // untrusted sidecar bytes inside an Error. Swallow it for a fixed message.
    let envelope: unknown;
    try {
      envelope = JSON.parse(raw);
    } catch {
      throw new OcrEngineError('ocr sidecar returned a malformed response');
    }
    const parsed = TesseractResponse.safeParse(envelope);
    if (!parsed.success) {
      throw new OcrEngineError('ocr sidecar returned a malformed response');
    }
    return parsed.data.text.slice(0, OCR_TEXT_MAX_CHARS);
  }

  private async readCapped(body: Awaited<ReturnType<OcrFetch>>['body']): Promise<string> {
    if (!body) {
      throw new OcrEngineError('ocr sidecar returned no body');
    }
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (!value) {
        continue;
      }
      total += value.byteLength;
      if (total > OCR_RESPONSE_MAX_BYTES) {
        throw new OcrEngineError('ocr sidecar response exceeded the size cap');
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
  }
}
