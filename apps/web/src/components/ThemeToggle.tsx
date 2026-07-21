'use client';

import { useEffect, useState, type ReactElement } from 'react';

type ThemePreference = 'system' | 'light' | 'dark';

/** Theme preference is a UI setting, not sensitive data — localStorage is fine. */
const STORAGE_KEY = 'estate-theme';

function applyToDocument(preference: ThemePreference): void {
  if (preference === 'system') {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = preference;
  }
}

export function ThemeToggle(): ReactElement {
  const [preference, setPreference] = useState<ThemePreference>('system');

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (stored === 'light' || stored === 'dark') setPreference(stored);
    } catch {
      // Storage unavailable (private mode etc.) — stay on system preference.
    }
  }, []);

  function choose(next: ThemePreference): void {
    setPreference(next);
    applyToDocument(next);
    try {
      if (next === 'system') {
        window.localStorage.removeItem(STORAGE_KEY);
      } else {
        window.localStorage.setItem(STORAGE_KEY, next);
      }
    } catch {
      // Storage unavailable — the choice still applies to this page view.
    }
  }

  return (
    <label className="flex items-center gap-2 text-sm text-ink-muted">
      Theme
      <select
        className="field-input w-auto py-1 text-sm"
        value={preference}
        onChange={(event) => choose(event.target.value as ThemePreference)}
      >
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  );
}
