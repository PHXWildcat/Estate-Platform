import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';
import { ThemeToggle } from '../components/ThemeToggle';
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

export default function RootLayout({ children }: { children: ReactNode }): ReactElement {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex min-h-screen flex-col">
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:rounded-field focus:bg-surface focus:px-3 focus:py-2 focus:text-sm"
        >
          Skip to main content
        </a>
        <header className="border-b border-line">
          <div className="mx-auto flex w-full max-w-3xl items-center justify-between px-6 py-4">
            <Link href="/" className="text-base font-semibold tracking-tight">
              Estate
            </Link>
            <nav aria-label="Main" className="flex items-center gap-6">
              <Link href="/security" className="text-sm text-ink-muted hover:text-ink">
                Security
              </Link>
              <ThemeToggle />
            </nav>
          </div>
        </header>
        <main id="main" className="mx-auto w-full max-w-3xl flex-1 px-6 py-10">
          {children}
        </main>
        <footer className="border-t border-line">
          <p className="mx-auto w-full max-w-3xl px-6 py-6 text-xs text-ink-muted">
            Milestone 1 walking skeleton. Your session lives in httpOnly cookies — this app never
            sees or stores tokens.
          </p>
        </footer>
      </body>
    </html>
  );
}
