import { sniffContent } from '../src/content-sniff';
import { pdfFixture } from './support';

const PNG = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.from('png-body')]);
const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.from('jpeg-body')]);
const TIFF_LE = Buffer.concat([Buffer.from('49492a00', 'hex'), Buffer.from('tiff-body')]);
const TIFF_BE = Buffer.concat([Buffer.from('4d4d002a', 'hex'), Buffer.from('tiff-body')]);

describe('sniffContent', () => {
  it('accepts each whitelisted format when declaration and bytes agree', () => {
    expect(sniffContent(pdfFixture('x'), 'application/pdf')).toEqual({
      format: 'pdf',
      mime: 'application/pdf',
    });
    expect(sniffContent(PNG, 'image/png')).toEqual({ format: 'png', mime: 'image/png' });
    expect(sniffContent(JPEG, 'image/jpeg')).toEqual({ format: 'jpeg', mime: 'image/jpeg' });
    expect(sniffContent(JPEG, 'image/jpg')).toEqual({ format: 'jpeg', mime: 'image/jpeg' });
    expect(sniffContent(TIFF_LE, 'image/tiff')).toEqual({ format: 'tiff', mime: 'image/tiff' });
    expect(sniffContent(TIFF_BE, 'image/tiff')).toEqual({ format: 'tiff', mime: 'image/tiff' });
    expect(sniffContent(pdfFixture('x'), 'APPLICATION/PDF')).not.toBeNull();
  });

  it('rejects declaration/bytes mismatches (polyglot mislabeling)', () => {
    expect(sniffContent(PNG, 'application/pdf')).toBeNull();
    expect(sniffContent(pdfFixture('x'), 'image/png')).toBeNull();
  });

  it('rejects undeclared and script-bearing types outright', () => {
    expect(sniffContent(Buffer.from('<svg onload=alert(1)>'), 'image/svg+xml')).toBeNull();
    expect(sniffContent(Buffer.from('<!doctype html>'), 'text/html')).toBeNull();
    expect(sniffContent(Buffer.from('MZ\x90\x00'), 'application/octet-stream')).toBeNull();
    expect(sniffContent(Buffer.from('PK\x03\x04'), 'application/zip')).toBeNull();
  });

  it('rejects bytes that match no whitelisted magic, whatever they claim', () => {
    expect(sniffContent(Buffer.from('plain text file'), 'application/pdf')).toBeNull();
    expect(sniffContent(Buffer.alloc(0), 'application/pdf')).toBeNull();
    expect(sniffContent(Buffer.from([0xff]), 'image/jpeg')).toBeNull();
  });
});
