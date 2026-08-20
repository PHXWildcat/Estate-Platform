import Link from 'next/link';
import type { ReactElement, ReactNode } from 'react';
import { MobileTabBar, RailNav } from './AppNav';
import { BrandMark } from './Brand';
import { RailAccount } from './RailAccount';
import { ThemeToggle } from './ThemeToggle';
import { OpenSettlementCaseBanner } from './OpenSettlementCaseBanner';
import { UnverifiedAddressBanner } from './UnverifiedAddressBanner';

/**
 * The Evergreen-rail app shell (2026-07-30 decision): a deep evergreen brand
 * rail that stays constant across color schemes, next to a quiet content
 * canvas that flips with them. Below `lg` the rail gives way to a slim brand
 * bar on top and a tab bar of the live destinations on the bottom.
 */
export function AppShell({ children }: { children: ReactNode }): ReactElement {
  return (
    <div className="flex min-h-screen flex-col lg:flex-row">
      {/* Mobile brand bar */}
      <header className="rail-surface flex items-center justify-between border-b border-rail-line bg-rail px-4 py-3 lg:hidden">
        <Link
          href="/"
          className="flex items-center gap-2.5 text-base font-semibold tracking-tight text-rail-ink"
        >
          <BrandMark tone="rail" />
          Estate
        </Link>
        <ThemeToggle tone="rail" />
      </header>

      {/* Desktop rail */}
      <aside className="rail-surface sticky top-0 hidden h-screen w-60 flex-none flex-col border-r border-rail-line bg-rail px-3 pb-4 pt-5 lg:flex">
        <Link
          href="/"
          className="flex items-center gap-2.5 px-2.5 pb-3 text-[1.0625rem] font-semibold tracking-tight text-rail-ink"
        >
          <BrandMark tone="rail" />
          Estate
        </Link>
        <RailNav />
        <div className="flex-1" />
        <div className="flex flex-col gap-3">
          <div className="px-2.5">
            <ThemeToggle tone="rail" />
          </div>
          <RailAccount />
        </div>
      </aside>

      {/* Content */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/*
          ORDERED BY URGENCY, not by age. An open death case outranks an
          unconfirmed address — and the two are related, because an
          unconfirmed address is part of why a case may have got this far
          without the owner hearing about it.
        */}
        <OpenSettlementCaseBanner />
        <UnverifiedAddressBanner />
        <main
          id="main"
          className="mx-auto w-full max-w-4xl flex-1 px-6 py-10 pb-24 lg:px-10 lg:pb-10"
        >
          {children}
        </main>
        <footer className="border-t border-line pb-20 lg:pb-0">
          <p className="mx-auto w-full max-w-4xl px-6 py-5 text-xs text-ink-muted lg:px-10">
            Your session lives in httpOnly cookies — this app never sees or stores tokens.
          </p>
        </footer>
      </div>

      <MobileTabBar />
    </div>
  );
}
