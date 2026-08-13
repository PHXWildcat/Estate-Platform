/**
 * The ceremony codec (M17 PR5). Pure functions, proven by round-trip: the
 * encoder and decoder are only correct TOGETHER, and a case that checked one
 * against hand-written base64url would re-derive the other by eye.
 */
import {
  base64urlToBytes,
  bytesToBase64url,
  ceremonyFailureMessage,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAuthenticationResponse,
  encodeRegistrationResponse,
  webauthnSupported,
} from './webauthn';

describe('base64url round trip', () => {
  it('survives every byte value, unpadded, URL-safe', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    const encoded = bytesToBase64url(bytes.buffer);
    expect(encoded).not.toMatch(/[+/=]/);
    expect([...base64urlToBytes(encoded)]).toEqual([...bytes]);
  });

  it('decodes the padded and unpadded forms identically', () => {
    // Identity emits unpadded (the WebAuthn JSON convention); a decoder that
    // required padding would fail every real challenge.
    expect([...base64urlToBytes('aGk')]).toEqual([...base64urlToBytes('aGk=')]);
  });
});

describe('options decoding', () => {
  it('converts exactly the binary fields of creation options and leaves the rest', () => {
    const wire = {
      challenge: bytesToBase64url(new Uint8Array([1, 2, 3]).buffer),
      rp: { id: 'localhost', name: 'Estate' },
      user: { id: bytesToBase64url(new Uint8Array([9, 9]).buffer), name: 'user-uuid' },
      excludeCredentials: [
        { id: bytesToBase64url(new Uint8Array([7]).buffer), transports: ['internal'] },
      ],
      authenticatorSelection: { userVerification: 'required' },
    };
    const decoded = decodeCreationOptions(wire) as unknown as {
      challenge: Uint8Array;
      rp: unknown;
      user: { id: Uint8Array; displayName: string };
      excludeCredentials: Array<{ id: Uint8Array; type: string; transports?: string[] }>;
      authenticatorSelection: unknown;
    };
    expect([...decoded.challenge]).toEqual([1, 2, 3]);
    expect([...decoded.user.id]).toEqual([9, 9]);
    // displayName synthesized when absent — the wire's name is an opaque uuid
    // by design (no PII in the ceremony) and the API requires the field.
    expect(decoded.user.displayName).toBe('user-uuid');
    expect(decoded.excludeCredentials[0]?.type).toBe('public-key');
    expect([...(decoded.excludeCredentials[0]?.id as Uint8Array)]).toEqual([7]);
    expect(decoded.rp).toEqual(wire.rp);
    expect(decoded.authenticatorSelection).toEqual(wire.authenticatorSelection);
  });

  it('converts request options, tolerating an absent allowCredentials', () => {
    const decoded = decodeRequestOptions({
      challenge: bytesToBase64url(new Uint8Array([5]).buffer),
    }) as unknown as { challenge: Uint8Array; allowCredentials: unknown[] };
    expect([...decoded.challenge]).toEqual([5]);
    expect(decoded.allowCredentials).toEqual([]);
  });
});

describe('response encoding', () => {
  function fakeCredential(response: unknown, attachment: string | null): PublicKeyCredential {
    return {
      id: 'cred-b64url',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      authenticatorAttachment: attachment,
      getClientExtensionResults: () => ({}),
      response,
    } as unknown as PublicKeyCredential;
  }

  it('encodes a registration response field for field', () => {
    const encoded = encodeRegistrationResponse(
      fakeCredential(
        {
          clientDataJSON: new Uint8Array([10]).buffer,
          attestationObject: new Uint8Array([11]).buffer,
          getTransports: () => ['internal'],
        },
        'platform',
      ),
    );
    expect(encoded).toEqual({
      id: 'cred-b64url',
      rawId: bytesToBase64url(new Uint8Array([1, 2]).buffer),
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: bytesToBase64url(new Uint8Array([10]).buffer),
        attestationObject: bytesToBase64url(new Uint8Array([11]).buffer),
        transports: ['internal'],
      },
    });
  });

  it('encodes an assertion, omitting an absent userHandle rather than sending null', () => {
    const encoded = encodeAuthenticationResponse(
      fakeCredential(
        {
          clientDataJSON: new Uint8Array([1]).buffer,
          authenticatorData: new Uint8Array([2]).buffer,
          signature: new Uint8Array([3]).buffer,
          userHandle: null,
        },
        null,
      ),
    );
    expect(encoded.response).toEqual({
      clientDataJSON: bytesToBase64url(new Uint8Array([1]).buffer),
      authenticatorData: bytesToBase64url(new Uint8Array([2]).buffer),
      signature: bytesToBase64url(new Uint8Array([3]).buffer),
    });
    expect('authenticatorAttachment' in encoded).toBe(false);
  });
});

describe('the browser-side failure vocabulary', () => {
  it('maps each DOMException to its own sentence, never to platform copy', () => {
    const closed = ceremonyFailureMessage(new DOMException('x', 'NotAllowedError'));
    const already = ceremonyFailureMessage(new DOMException('x', 'InvalidStateError'));
    const refused = ceremonyFailureMessage(new DOMException('x', 'SecurityError'));
    const unknown = ceremonyFailureMessage(new Error('?'));
    // Four distinct facts, four distinct sentences — and the cancellation one
    // says nothing was changed, because a closed sheet must not read as a
    // platform refusal (the M9 rule's client-side mirror).
    expect(new Set([closed, already, refused, unknown]).size).toBe(4);
    expect(closed).toContain('Nothing was changed');
  });

  it('reports support honestly in this environment', () => {
    // jsdom has no PublicKeyCredential: the honest answer is false, and the
    // surface renders its unavailable copy rather than a broken button — the
    // faithful-about-absence rule the M16 chrome-double lesson is about.
    expect(webauthnSupported()).toBe(false);
  });
});
