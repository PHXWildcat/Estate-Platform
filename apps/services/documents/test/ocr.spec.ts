import { DetectDocumentTextCommand } from '@aws-sdk/client-textract';
import { OCR_TEXT_MAX_CHARS, StubOcr, TextractOcr } from '../src/ocr';
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
