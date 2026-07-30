import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';
import { BrandMark } from '../../components/Brand';
import { ThemeToggle } from '../../components/ThemeToggle';

/**
 * Sign-in and registration render without app navigation: a signed-out page
 * wearing the estate's rail would promise access it cannot grant. Just the
 * brand (a way back home), the theme control, and the form.
 */
export default function AuthLayout({ children }: { children: ReactNode }): ReactElement {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="mx-auto flex w-full max-w-md items-center justify-between px-6 pb-2 pt-6">
        <Link href="/" className="flex items-center gap-2.5 text-base font-semibold tracking-tight">
          <BrandMark />
          Estate
        </Link>
        <ThemeToggle />
      </header>
      <main id="main" className="mx-auto w-full max-w-md flex-1 px-6 py-10">
        {children}
      </main>
      <footer>
        <p className="mx-auto w-full max-w-md px-6 py-6 text-xs text-ink-muted">
          Your session lives in httpOnly cookies — this app never sees or stores tokens.
        </p>
      </footer>
    </div>
  );
}
