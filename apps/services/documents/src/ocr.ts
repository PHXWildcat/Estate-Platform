import { DetectDocumentTextCommand, type TextractClient } from '@aws-sdk/client-textract';

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
