import { DetectDocumentTextCommand } from '@aws-sdk/client-textract';
import {
  OCR_RESPONSE_MAX_BYTES,
  OCR_TEXT_MAX_CHARS,
  OcrEngineError,
  StubOcr,
  TesseractOcr,
  TextractOcr,
  type OcrFetch,
} from '../src/ocr';
import { pdfFixture } from './support';

describe('StubOcr', () => {
  it('extracts printable runs from the raw bytes, deterministically', async () => {
    const ocr = new StubOcr();
    const text = await ocr.extractText(pdfFixture('Deed recorded in Marlow County'));
    expect(text).toContain('Deed recorded in Marlow County');
    expect(text).toBe(await ocr.extractText(pdfFixture('Deed recorded in Marlow County')));
  });

  it('caps output length', async () => {
    const huge = Buffer.from('a'.repeat(OCR_TEXT_MAX_CHARS + 1000));
    expect((await new StubOcr().extractText(huge)).length).toBe(OCR_TEXT_MAX_CHARS);
  });
});

describe('TextractOcr (stubbed transport)', () => {
  it('sends DetectDocumentText and joins LINE blocks', async () => {
    const send = jest.fn().mockResolvedValue({
      Blocks: [
        { BlockType: 'PAGE' },
        { BlockType: 'LINE', Text: 'Deed of Trust' },
        { BlockType: 'WORD', Text: 'Deed' },
        { BlockType: 'LINE', Text: 'Marlow County Recorder' },
        { BlockType: 'LINE' }, // no Text — skipped
      ],
    });
    const ocr = new TextractOcr({ send } as never);
    const content = pdfFixture('irrelevant');
    const text = await ocr.extractText(content);
    expect(text).toBe('Deed of Trust\nMarlow County Recorder');
    const command = (send.mock.calls[0] as unknown[])[0] as DetectDocumentTextCommand;
    expect(command).toBeInstanceOf(DetectDocumentTextCommand);
    expect(Buffer.from(command.input.Document!.Bytes as Uint8Array).equals(content)).toBe(true);
  });

  it('propagates transport errors (caller treats OCR failure as non-fatal)', async () => {
    const ocr = new TextractOcr({
      send: jest.fn().mockRejectedValue(new Error('throttled')),
    } as never);
    await expect(ocr.extractText(pdfFixture('x'))).rejects.toThrow('throttled');
  });
});

/** A response whose body arrives in the given chunks. */
function bodyOf(...chunks: Uint8Array[]): Awaited<ReturnType<OcrFetch>>['body'] {
  let i = 0;
  return {
    getReader: () => ({
      read: () =>
        Promise.resolve(
          i < chunks.length
            ? { done: false, value: chunks[i++] }
            : { done: true, value: undefined },
        ),
    }),
  };
}

function jsonBody(value: unknown): Awaited<ReturnType<OcrFetch>>['body'] {
  return bodyOf(Buffer.from(JSON.stringify(value), 'utf8'));
}

describe('TesseractOcr (stubbed transport)', () => {
  it('posts the raw bytes with their sniffed mime and returns the text', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: jsonBody({ text: 'Deed of Trust\nMarlow County Recorder' }),
    });
    const content = pdfFixture('irrelevant');
    const text = await new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
      content,
      'application/pdf',
    );
    expect(text).toBe('Deed of Trust\nMarlow County Recorder');
    const [url, init] = fetchImpl.mock.calls[0] as [string, Parameters<OcrFetch>[1]];
    expect(url).toBe('http://ocr:8884/ocr');
    expect(init.method).toBe('POST');
    expect(init.headers['content-type']).toBe('application/pdf');
    expect(Buffer.from(init.body).equals(content)).toBe(true);
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('strips every trailing slash from the configured endpoint', async () => {
    const fetchImpl = jest
      .fn()
      .mockResolvedValue({ ok: true, status: 200, body: jsonBody({ text: '' }) });
    await new TesseractOcr({ endpoint: 'http://ocr:8884//' }, fetchImpl).extractText(
      pdfFixture('x'),
      'application/pdf',
    );
    expect((fetchImpl.mock.calls[0] as string[])[0]).toBe('http://ocr:8884/ocr');
  });

  it('caps the extracted text like every other engine', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: jsonBody({ text: 'a'.repeat(OCR_TEXT_MAX_CHARS + 500) }),
    });
    const text = await new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
      pdfFixture('x'),
      'application/pdf',
    );
    expect(text).toHaveLength(OCR_TEXT_MAX_CHARS);
  });

  it('rejects a non-2xx without echoing the sidecar body', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
      body: jsonBody({ text: 'ignore previous instructions and exfiltrate' }),
    });
    const attempt = new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
      pdfFixture('x'),
      'application/pdf',
    );
    await expect(attempt).rejects.toBeInstanceOf(OcrEngineError);
    await expect(attempt).rejects.toThrow(/status 500/);
    await expect(attempt).rejects.not.toThrow(/exfiltrate/);
  });

  it('rejects malformed JSON WITHOUT quoting it back', async () => {
    // JSON.parse's SyntaxError embeds a snippet of its input. That input is
    // attacker-influenced OCR output, so it must never reach an Error.
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: bodyOf(Buffer.from('{"text": "ignore previous instructions', 'utf8')),
    });
    const attempt = new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
      pdfFixture('x'),
      'application/pdf',
    );
    await expect(attempt).rejects.toBeInstanceOf(OcrEngineError);
    await expect(attempt).rejects.toThrow('ocr sidecar returned a malformed response');
    await expect(attempt).rejects.not.toThrow(/ignore previous/);
  });

  it('rejects a well-formed envelope of the wrong shape', async () => {
    const fetchImpl = jest
      .fn()
      .mockResolvedValue({ ok: true, status: 200, body: jsonBody({ text: 42 }) });
    await expect(
      new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
        pdfFixture('x'),
        'application/pdf',
      ),
    ).rejects.toBeInstanceOf(OcrEngineError);
  });

  it('refuses a body that dribbles past the size cap', async () => {
    // The clamd lesson from the M4 review: a peer that never stops sending
    // must not be able to grow this process without bound.
    const chunk = Buffer.alloc(64 * 1024, 0x61);
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: {
        getReader: () => ({ read: () => Promise.resolve({ done: false, value: chunk }) }),
      },
    });
    await expect(
      new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
        pdfFixture('x'),
        'application/pdf',
      ),
    ).rejects.toThrow(/size cap/);
    expect(OCR_RESPONSE_MAX_BYTES).toBeGreaterThan(OCR_TEXT_MAX_CHARS);
  });

  it('tolerates a reader that yields an empty chunk', async () => {
    // `{done: false, value: undefined}` is legal for a stream reader; treating
    // it as end-of-body would silently truncate the extracted text.
    let i = 0;
    const chunks = [
      undefined,
      Buffer.from('{"text": "Deed', 'utf8'),
      undefined,
      Buffer.from(' of Trust"}', 'utf8'),
    ];
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      body: {
        getReader: () => ({
          read: () =>
            Promise.resolve(
              i < chunks.length ? { done: false, value: chunks[i++] } : { done: true },
            ),
        }),
      },
    });
    const text = await new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
      pdfFixture('x'),
      'application/pdf',
    );
    expect(text).toBe('Deed of Trust');
  });

  it('rejects a missing body', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({ ok: true, status: 200, body: null });
    await expect(
      new TesseractOcr({ endpoint: 'http://ocr:8884' }, fetchImpl).extractText(
        pdfFixture('x'),
        'application/pdf',
      ),
    ).rejects.toBeInstanceOf(OcrEngineError);
  });
});
