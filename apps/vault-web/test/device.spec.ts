/**
 * @jest-environment jsdom
 */

/**
 * The two device-local behaviours: what this browser remembers, and what it
 * puts on the clipboard (M15 PR2).
 *
 * Both are places where the honest thing and the convenient thing diverge, so
 * the assertions are mostly about the limits rather than the happy path.
 */
import 'fake-indexeddb/auto';
import { CLIPBOARD_CLEAR_MS, clearNow, copyWithAutoClear } from '../src/client/clipboard';
import {
  forgetSecretKey,
  recallSecretKey,
  rememberSecretKey,
} from '../src/client/secret-key-store';
import { downloadEmergencyKit, EMERGENCY_KIT_FILENAME } from '../src/client/emergency-kit';

const USER = 'user-a';
const OTHER = 'user-b';

describe('the Secret Key on this device', () => {
  afterEach(async () => {
    await forgetSecretKey(USER);
    await forgetSecretKey(OTHER);
  });

  it('remembers and recalls the raw bytes', async () => {
    const entropy = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    await rememberSecretKey(USER, entropy);
    expect(await recallSecretKey(USER)).toEqual(entropy);
  });

  it('stores a COPY, so the caller wiping its buffer does not blank the record', async () => {
    // `enroll` wipes its entropy the moment the user clicks past the screen. A
    // stored VIEW onto that buffer would silently become sixteen zero bytes —
    // a device that thinks it remembers a key it cannot use.
    const entropy = new Uint8Array(16).fill(7);
    await rememberSecretKey(USER, entropy);
    entropy.fill(0);
    expect(await recallSecretKey(USER)).toEqual(new Uint8Array(16).fill(7));
  });

  it('keeps accounts separate on a shared device', async () => {
    await rememberSecretKey(USER, new Uint8Array(16).fill(1));
    await rememberSecretKey(OTHER, new Uint8Array(16).fill(2));
    expect(await recallSecretKey(USER)).toEqual(new Uint8Array(16).fill(1));
    expect(await recallSecretKey(OTHER)).toEqual(new Uint8Array(16).fill(2));
  });

  it('answers null for a device that has never been told', async () => {
    expect(await recallSecretKey('nobody')).toBeNull();
  });

  it('forgets on request — which is also what reset must do', async () => {
    await rememberSecretKey(USER, new Uint8Array(16).fill(3));
    await forgetSecretKey(USER);
    expect(await recallSecretKey(USER)).toBeNull();
  });
});

describe('clipboard auto-clear', () => {
  let written: string[];

  beforeEach(() => {
    jest.useFakeTimers();
    written = [];
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: (text: string) => {
          written.push(text);
          return Promise.resolve();
        },
      },
      configurable: true,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('copies, then clears after the stated delay', async () => {
    expect(await copyWithAutoClear('a-secret')).toBe('copied');
    expect(written).toEqual(['a-secret']);

    jest.advanceTimersByTime(CLIPBOARD_CLEAR_MS - 1);
    expect(written).toEqual(['a-secret']);

    jest.advanceTimersByTime(1);
    expect(written).toEqual(['a-secret', '']);
  });

  it('a second copy REPLACES the pending clear rather than adding one', async () => {
    // Otherwise the first timer would wipe the second value early — a user who
    // copies twice would find their clipboard empty before they could paste.
    await copyWithAutoClear('first');
    jest.advanceTimersByTime(CLIPBOARD_CLEAR_MS - 100);
    await copyWithAutoClear('second');

    jest.advanceTimersByTime(200);
    expect(written).toEqual(['first', 'second']); // no clear yet
    jest.advanceTimersByTime(CLIPBOARD_CLEAR_MS);
    expect(written).toEqual(['first', 'second', '']);
  });

  it('reports UNAVAILABLE rather than pretending, when the API is absent', async () => {
    // An insecure context or an old browser. The UI has to tell the user to
    // select the field themselves; silently doing nothing is the worst option.
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    expect(await copyWithAutoClear('a-secret')).toBe('unavailable');
  });

  it('clearNow cancels the pending timer and clears immediately', async () => {
    await copyWithAutoClear('a-secret');
    clearNow();
    expect(written).toEqual(['a-secret', '']);
    // And the cancelled timer does not fire a second clear later.
    jest.advanceTimersByTime(CLIPBOARD_CLEAR_MS * 2);
    expect(written).toEqual(['a-secret', '']);
  });
});

describe('the emergency kit download', () => {
  it('hands the browser a text file and revokes the object URL immediately', () => {
    // Leaving the URL live would keep the Secret Key reachable from a `blob:`
    // URL for the life of the document — a second copy nobody asked for.
    const created: string[] = [];
    const revoked: string[] = [];
    Object.defineProperty(URL, 'createObjectURL', {
      value: () => {
        const url = `blob:fake-${created.length}`;
        created.push(url);
        return url;
      },
      configurable: true,
    });
    Object.defineProperty(URL, 'revokeObjectURL', {
      value: (url: string) => revoked.push(url),
      configurable: true,
    });

    let downloadAttr = '';
    const click = jest
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function mockClick(this: HTMLAnchorElement) {
        downloadAttr = this.download;
      });

    downloadEmergencyKit({
      secretKey: 'ES1-AAAAA-BBBBB-CCCCC-DDDDD',
      accountLabel: 'user-uuid',
      issuedAt: '2026-08-08',
    });

    expect(downloadAttr).toBe(EMERGENCY_KIT_FILENAME);
    expect(revoked).toEqual(created);
    click.mockRestore();
  });
});
