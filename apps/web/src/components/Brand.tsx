import type { ReactElement } from 'react';

/**
 * The Estate mark: three ledger lines in a rounded square. `tone` picks the
 * fill for the surface it sits on — accent block on light surfaces, rail
 * accent on the evergreen rail (where a dark-green block would vanish).
 */
export function BrandMark({ tone = 'surface' }: { tone?: 'surface' | 'rail' }): ReactElement {
  const box = tone === 'rail' ? 'var(--rail-accent)' : 'var(--accent)';
  const bars = tone === 'rail' ? 'var(--rail)' : 'var(--on-accent)';
  return (
    <svg width="22" height="22" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
      <rect width="12" height="12" rx="3" fill={box} />
      <rect x="2" y="2.4" width="8" height="1.6" rx="0.8" fill={bars} />
      <rect x="2" y="5.2" width="8" height="1.6" rx="0.8" fill={bars} />
      <rect x="2" y="8" width="5.2" height="1.6" rx="0.8" fill={bars} />
    </svg>
  );
}
