'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactElement } from 'react';
import { Icon, type IconName } from './icons';

/**
 * Navigation for the Evergreen-rail shell (2026-07-30 decision). One config
 * drives both the desktop rail and the mobile bottom tab bar.
 *
 * "Soon" entries are surfaces whose BACKENDS already shipped (documents M4,
 * vault M6, people/roles M7) without a UI — they render as inert previews, not
 * links, so the shell shows the product's shape without dead ends. Vault will
 * additionally live on an ISOLATED ORIGIN (docs/03 TB6), so when it goes live
 * its entry becomes an outbound link, never an in-app route.
 */

interface NavItem {
  label: string;
  icon: IconName;
  /** Absent for "Soon" entries — they are previews, not destinations. */
  href?: '/' | '/assets' | '/security';
  /** Active only on exact match (the Overview item, so "/" ≠ everything). */
  exact?: boolean;
}

export const NAV_GROUPS: ReadonlyArray<{ label: string; items: readonly NavItem[] }> = [
  {
    label: 'Estate',
    items: [
      { label: 'Overview', icon: 'overview', href: '/', exact: true },
      { label: 'Assets', icon: 'assets', href: '/assets' },
      { label: 'Documents', icon: 'documents' },
      { label: 'People', icon: 'people' },
    ],
  },
  {
    label: 'Protection',
    items: [
      { label: 'Vault', icon: 'vault' },
      { label: 'Security', icon: 'security', href: '/security' },
    ],
  },
];

function isActive(item: NavItem, pathname: string): boolean {
  if (item.href === undefined) return false;
  if (item.exact === true) return pathname === item.href;
  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}

export function RailNav(): ReactElement {
  const pathname = usePathname();
  return (
    <nav aria-label="Main">
      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <span className="rail-group">{group.label}</span>
          {group.items.map((item) =>
            item.href !== undefined ? (
              <Link
                key={item.label}
                href={item.href}
                className="rail-item"
                aria-current={isActive(item, pathname) ? 'page' : undefined}
              >
                <Icon name={item.icon} />
                {item.label}
              </Link>
            ) : (
              <span key={item.label} className="rail-item opacity-55">
                <Icon name={item.icon} />
                {item.label}
                <span className="rail-soon">Soon</span>
              </span>
            ),
          )}
        </div>
      ))}
    </nav>
  );
}

/** The three live destinations as a fixed bottom bar, small screens only. */
export function MobileTabBar(): ReactElement {
  const pathname = usePathname();
  const live = NAV_GROUPS.flatMap((group) => group.items).filter(
    (item): item is NavItem & { href: NonNullable<NavItem['href']> } => item.href !== undefined,
  );
  return (
    <nav
      aria-label="Main"
      className="rail-surface fixed inset-x-0 bottom-0 z-10 flex border-t border-rail-line bg-rail lg:hidden"
    >
      {live.map((item) => {
        const active = isActive(item, pathname);
        return (
          <Link
            key={item.label}
            href={item.href}
            aria-current={active ? 'page' : undefined}
            className={`flex flex-1 flex-col items-center gap-1 py-2.5 text-[0.6875rem] font-medium ${
              active ? 'text-rail-accent' : 'text-rail-muted'
            }`}
          >
            <Icon name={item.icon} size={19} />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}
