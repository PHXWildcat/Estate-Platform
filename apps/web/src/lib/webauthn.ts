/**
 * The WebAuthn ceremony codec (M17 PR5) — the bridge between identity's JSON
 * wire (base64url strings, @simplewebauthn/server's format) and the browser's
 * `navigator.credentials` API (ArrayBuffers).
 *
 * HAND-ROLLED, NOT A DEPENDENCY, on the precedent this repo keeps applying to
 * exactly this class of code: the node:crypto webhook verifier, the template
 * renderer, the clamd client, the vault origin's SRP. The obvious helper
 * (@simplewebauthn/browser) would put a third-party tree on the path that
 * handles second-factor material, to save ~sixty lines of mechanical
 * conversion. The conversion IS mechanical — base64url to bytes and back, over
 * a fixed set of fields named by the WebAuthn Level 2 JSON serialization — and
 * a fixed field list is also the honest shape: a codec that walked the object
 * generically would convert fields this code has never thought about.
 *
 * WHAT THIS FILE NEVER DOES: validate. Attestation semantics belong to
 * identity's library; a browser-side opinion would be the client-side second
 * opinion the M12 upload rule forbids.
 */

export function base64urlToBytes(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64url(bytes: ArrayBuffer): string {
  const view = new Uint8Array(bytes);
  let raw = '';
  for (let i = 0; i < view.length; i += 1) {
    raw += String.fromCharCode(view[i] as number);
  }
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface WireDescriptor {
  id: string;
  type?: string;
  transports?: string[];
}

/** Identity's creation-options JSON → what navigator.credentials.create wants. */
export function decodeCreationOptions(options: {
  challenge: string;
  user: { id: string; name: string; displayName?: string };
  excludeCredentials?: WireDescriptor[];
  [key: string]: unknown;
}): PublicKeyCredentialCreationOptions {
  return {
    ...options,
    challenge: base64urlToBytes(options.challenge),
    user: {
      name: options.user.name,
      displayName: options.user.displayName ?? options.user.name,
      id: base64urlToBytes(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials ?? []).map((cred) => ({
      type: 'public-key',
      id: base64urlToBytes(cred.id),
      ...(cred.transports ? { transports: cred.transports as AuthenticatorTransport[] } : {}),
    })),
  } as unknown as PublicKeyCredentialCreationOptions;
}

/** Identity's request-options JSON → what navigator.credentials.get wants. */
export function decodeRequestOptions(options: {
  challenge: string;
  allowCredentials?: WireDescriptor[];
  [key: string]: unknown;
}): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64urlToBytes(options.challenge),
    allowCredentials: (options.allowCredentials ?? []).map((cred) => ({
      type: 'public-key',
      id: base64urlToBytes(cred.id),
      ...(cred.transports ? { transports: cred.transports as AuthenticatorTransport[] } : {}),
    })),
  } as unknown as PublicKeyCredentialRequestOptions;
}

/** A created credential → the registration JSON identity's library verifies. */
export function encodeRegistrationResponse(credential: PublicKeyCredential): {
  id: string;
  rawId: string;
  type: string;
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: string;
  response: Record<string, unknown>;
} {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    response: {
      clientDataJSON: bytesToBase64url(response.clientDataJSON),
      attestationObject: bytesToBase64url(response.attestationObject),
      ...(typeof response.getTransports === 'function'
        ? { transports: response.getTransports() }
        : {}),
    },
  };
}

/** An assertion → the authentication JSON identity's library verifies. */
export function encodeAuthenticationResponse(credential: PublicKeyCredential): {
  id: string;
  rawId: string;
  type: string;
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: string;
  response: Record<string, unknown>;
} {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults() as Record<string, unknown>,
    ...(credential.authenticatorAttachment
      ? { authenticatorAttachment: credential.authenticatorAttachment }
      : {}),
    response: {
      clientDataJSON: bytesToBase64url(response.clientDataJSON),
      authenticatorData: bytesToBase64url(response.authenticatorData),
      signature: bytesToBase64url(response.signature),
      ...(response.userHandle ? { userHandle: bytesToBase64url(response.userHandle) } : {}),
    },
  };
}

/**
 * Whether this browser can do the ceremony at all. A absent API renders the
 * whole surface as unavailable copy, never a broken button.
 */
export function webauthnSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function';
}

/**
 * The browser-side failure vocabulary. These never reach errorCopy — they are
 * facts about THIS ceremony on THIS device, not platform refusals: the user
 * closed the sheet, the authenticator timed out, or the browser refused the
 * origin. Mapping them to a BFF code would launder a local fact into a
 * platform one (the M9 rule's client-side mirror: a cancellation must not
 * read as an outage).
 */
export function ceremonyFailureMessage(err: unknown): string {
  if (err instanceof DOMException) {
    if (err.name === 'NotAllowedError') {
      return 'The passkey prompt was closed or timed out. Nothing was changed — try again when ready.';
    }
    if (err.name === 'InvalidStateError') {
      return 'This device is already registered as a passkey on this account.';
    }
    if (err.name === 'SecurityError') {
      return 'This browser refused the passkey ceremony for this site.';
    }
  }
  return 'The passkey ceremony could not start on this device.';
}
