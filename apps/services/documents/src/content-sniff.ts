import type { UploadFormat } from '@estate/contracts';

/**
 * Upload content-type validation (docs/03: uploaded documents are untrusted
 * input; parsers over them are a fuzzing target). The DECLARED mime is never
 * trusted: the magic bytes decide, and a mismatch between declaration and
 * bytes rejects the upload — a polyglot that says "pdf" but starts like
 * something else never reaches the scanner verdict path mislabeled.
 *
 * Allowlist only: PDF and the OCR-able raster formats. Everything else —
 * including HTML, SVG (script-bearing), and office formats — is refused.
 */

export interface SniffedType {
  readonly format: UploadFormat;
  readonly mime: string;
}

const ALLOWED: ReadonlyArray<{
  format: UploadFormat;
  mime: string;
  matches: (b: Buffer) => boolean;
}> = [
  {
    format: 'pdf',
    mime: 'application/pdf',
    matches: (b) => b.subarray(0, 5).equals(Buffer.from('%PDF-', 'ascii')),
  },
  {
    format: 'png',
    mime: 'image/png',
    matches: (b) => b.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')),
  },
  {
    format: 'jpeg',
    mime: 'image/jpeg',
    matches: (b) => b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  },
  {
    format: 'tiff',
    mime: 'image/tiff',
    matches: (b) =>
      b.subarray(0, 4).equals(Buffer.from('49492a00', 'hex')) ||
      b.subarray(0, 4).equals(Buffer.from('4d4d002a', 'hex')),
  },
];

/** Mimes accepted from the client, mapped to the format they must sniff as. */
const DECLARED_MIMES = new Map<string, UploadFormat>([
  ['application/pdf', 'pdf'],
  ['image/png', 'png'],
  ['image/jpeg', 'jpeg'],
  ['image/jpg', 'jpeg'],
  ['image/tiff', 'tiff'],
]);

/**
 * Returns the sniffed type iff the bytes match a whitelisted format AND the
 * client's declared mime agrees; null otherwise (caller rejects with 422).
 */
export function sniffContent(content: Buffer, declaredMime: string): SniffedType | null {
  const declared = DECLARED_MIMES.get(declaredMime.toLowerCase());
  if (!declared) {
    return null;
  }
  const sniffed = ALLOWED.find((candidate) => candidate.matches(content));
  if (!sniffed || sniffed.format !== declared) {
    return null;
  }
  return { format: sniffed.format, mime: sniffed.mime };
}
