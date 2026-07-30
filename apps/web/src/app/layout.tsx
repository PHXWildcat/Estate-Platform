import type { Metadata } from 'next';
import type { ReactElement, ReactNode } from 'react';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'Estate', template: '%s — Estate' },
  description: 'Organize your estate with security designed for the things that matter most.',
};

/**
 * Applies a stored manual theme choice before first paint to avoid a flash of
 * the wrong scheme. Static string, no user input — safe to inline.
 */
const themeInitScript =
  "(function(){try{var t=localStorage.getItem('estate-theme');if(t==='light'||t==='dark'){document.documentElement.dataset.theme=t;}}catch(e){}})();";

/**
 * Chrome lives in the route-group layouts: `(app)` wraps pages in the
 * Evergreen-rail AppShell; `(auth)` renders sign-in/register without app
 * navigation. Both groups provide the `#main` landmark this skip link targets.
 */
export default function RootLayout({ children }: { children: ReactNode }): ReactElement {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="min-h-screen">
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
        <link
          rel="preload"
          href="/fonts/instrument-sans-latin.woff2"
          as="font"
          type="font/woff2"
          crossOrigin="anonymous"
        />
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-20 focus:rounded-field focus:bg-surface focus:px-3 focus:py-2 focus:text-sm"
        >
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
