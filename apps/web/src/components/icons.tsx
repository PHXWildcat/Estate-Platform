import type { ReactElement } from 'react';

/**
 * Line icons for the app shell, drawn on an 18×18 grid at stroke 1.5.
 * Hand-authored and dependency-free (the vault-crypto "no packages on
 * sensitive surfaces" habit, applied to pixels): every glyph is a handful of
 * primitive shapes, `currentColor`, decorative-only (`aria-hidden`).
 */

export type IconName =
  'overview' | 'assets' | 'documents' | 'people' | 'vault' | 'security' | 'sign-out';

const PATHS: Record<IconName, ReactElement> = {
  overview: (
    <>
      <rect x="2.5" y="2.5" width="5.4" height="5.4" rx="1.4" />
      <rect x="10.1" y="2.5" width="5.4" height="5.4" rx="1.4" />
      <rect x="2.5" y="10.1" width="5.4" height="5.4" rx="1.4" />
      <rect x="10.1" y="10.1" width="5.4" height="5.4" rx="1.4" />
    </>
  ),
  assets: (
    <>
      <ellipse cx="9" cy="5.2" rx="6" ry="2.6" />
      <path d="M3 5.2v7.4c0 1.5 2.7 2.7 6 2.7s6-1.2 6-2.7V5.2" strokeLinecap="round" />
    </>
  ),
  documents: (
    <>
      <path
        d="M5 2.5h5.6L14.5 6.4v8.1a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-11a1 1 0 0 1 1-1z"
        strokeLinejoin="round"
      />
      <path d="M10.6 2.5V6.4h3.9" />
    </>
  ),
  people: (
    <>
      <circle cx="6.6" cy="6.4" r="2.6" />
      <path d="M2.4 15c0-2.6 1.9-4.2 4.2-4.2s4.2 1.6 4.2 4.2" strokeLinecap="round" />
      <path d="M11.8 4.4a2.6 2.6 0 0 1 0 4M13.4 11.2c1.4.6 2.2 1.9 2.2 3.8" strokeLinecap="round" />
    </>
  ),
  vault: (
    <>
      <path
        d="M9 2l6 2.3v4.2c0 3.8-2.6 6.4-6 7.5-3.4-1.1-6-3.7-6-7.5V4.3L9 2z"
        strokeLinejoin="round"
      />
      <circle cx="9" cy="8.6" r="1.7" />
    </>
  ),
  security: (
    <>
      <rect x="4" y="8" width="10" height="7" rx="1.5" />
      <path d="M6.2 8V5.8a2.8 2.8 0 0 1 5.6 0V8" strokeLinecap="round" />
    </>
  ),
  'sign-out': (
    <path
      d="M11.5 6V4a1.5 1.5 0 0 0-1.5-1.5H4A1.5 1.5 0 0 0 2.5 4v10A1.5 1.5 0 0 0 4 15.5h6a1.5 1.5 0 0 0 1.5-1.5v-2M7.5 9h8m0 0-2.4-2.4M15.5 9l-2.4 2.4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  ),
};

export function Icon({ name, size = 17 }: { name: IconName; size?: number }): ReactElement {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 18 18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}
