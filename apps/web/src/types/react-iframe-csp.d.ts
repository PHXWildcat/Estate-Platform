import 'react';

/**
 * `<iframe csp>` — Chromium's per-frame Content-Security-Policy attribute.
 *
 * It is real HTML that React passes straight through to the DOM, but
 * @types/react does not declare it, so `DocumentViewer`'s third containment
 * layer would otherwise be a type error. Declared narrowly — one attribute on
 * one element — rather than by widening the element's props, and in its own
 * file because the leading import is what makes this an AUGMENTATION of the
 * react module rather than a replacement of it.
 */
declare module 'react' {
  // The type parameter is part of the interface being augmented and is unused
  // by the one member added here.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface IframeHTMLAttributes<T> {
    csp?: string;
  }
}
