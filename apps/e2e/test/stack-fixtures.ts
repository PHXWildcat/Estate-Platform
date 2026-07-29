import { deflateSync } from 'node:zlib';

/**
 * Deterministic PNG fixtures for the stack test, built with node:zlib and
 * nothing else — an image library on the test's dependency tree would be a
 * strange price for two tiny bitmaps.
 *
 * - `textPng(text)`: white canvas, large black block glyphs from an in-file
 *   5x7 font. Real OCR input: tesseract must actually read it.
 * - `malwarePng()`: a valid PNG whose tEXt chunk carries the byte pattern
 *   `infra/clamav/stack-test.ndb` declares. Sniffing admits it (real PNG
 *   magic); clamd must flag it (`Estate.Stack.TestProbe`).
 */

/** Must match infra/clamav/stack-test.ndb exactly. */
export const MALWARE_PROBE_PATTERN = 'ESTATE-STACK-MALWARE-PROBE-7f3a';

// --- minimal 5x7 font: exactly the glyphs the fixtures use -----------------
const FONT: Record<string, readonly number[]> = {
  // Each glyph: 7 rows of 5 bits, MSB left.
  A: [0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001],
  B: [0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110],
  C: [0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110],
  E: [0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111],
  K: [0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001],
  O: [0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110],
  P: [0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000],
  R: [0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001],
  S: [0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110],
  T: [0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100],
  ' ': [0, 0, 0, 0, 0, 0, 0],
};

const CRC_TABLE = ((): Uint32Array => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(...parts: Buffer[]): number {
  let crc = 0xffffffff;
  for (const part of parts) {
    for (const byte of part) {
      crc = (CRC_TABLE[(crc ^ byte) & 0xff] as number) ^ (crc >>> 8);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type: string, data: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const typeBuffer = Buffer.from(type, 'latin1');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeBuffer, data));
  return Buffer.concat([length, typeBuffer, data, crc]);
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/** Grayscale 8-bit PNG from a pixel callback. */
function grayscalePng(
  width: number,
  height: number,
  pixel: (x: number, y: number) => number,
  extraChunks: Buffer[] = [],
): Buffer {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // grayscale
  // compression 0, filter 0, interlace 0
  const raw = Buffer.alloc(height * (width + 1));
  for (let y = 0; y < height; y++) {
    raw[y * (width + 1)] = 0; // filter: none
    for (let x = 0; x < width; x++) {
      raw[y * (width + 1) + 1 + x] = pixel(x, y);
    }
  }
  return Buffer.concat([
    PNG_SIGNATURE,
    chunk('IHDR', ihdr),
    ...extraChunks,
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/**
 * Render `text` (letters covered by FONT only) as large black-on-white
 * glyphs. Scale 12 puts a 5x7 glyph at 60x84 px — comfortably inside
 * tesseract's happy zone for clean synthetic text.
 */
export function textPng(text: string): Buffer {
  const scale = 12;
  const margin = 4 * scale;
  const glyphW = 6; // 5 + 1 spacing
  const width = margin * 2 + text.length * glyphW * scale;
  const height = margin * 2 + 7 * scale;
  const glyphs = [...text].map((ch) => {
    const glyph = FONT[ch];
    if (!glyph) {
      throw new Error(`textPng font has no glyph for "${ch}"`);
    }
    return glyph;
  });
  return grayscalePng(width, height, (x, y) => {
    const gx = x - margin;
    const gy = y - margin;
    if (gx < 0 || gy < 0 || gy >= 7 * scale) {
      return 255;
    }
    const index = Math.floor(gx / (glyphW * scale));
    const glyph = glyphs[index];
    if (!glyph) {
      return 255;
    }
    const col = Math.floor((gx - index * glyphW * scale) / scale);
    const row = Math.floor(gy / scale);
    if (col >= 5) {
      return 255; // inter-glyph spacing
    }
    return ((glyph[row] as number) >> (4 - col)) & 1 ? 0 : 255;
  });
}

/** A valid PNG that trips the stack-test ClamAV signature. */
export function malwarePng(): Buffer {
  const payload = Buffer.concat([
    Buffer.from('Comment\0', 'latin1'),
    Buffer.from(MALWARE_PROBE_PATTERN, 'latin1'),
  ]);
  return grayscalePng(4, 4, () => 128, [chunk('tEXt', payload)]);
}
