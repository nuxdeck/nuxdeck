// SPDX-License-Identifier: AGPL-3.0-only

export type Theme = 'system' | 'light' | 'dark';
export type Density = 'comfortable' | 'compact';

const THEME_KEY = 'nux.theme';
const DENSITY_KEY = 'nux.density';
const THEME_ORDER: readonly Theme[] = ['system', 'light', 'dark'];

// Storage can be missing or throw (private windows, blocked site data); the UI must still work.
function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* the choice then lasts for this page view only */
  }
}

class Appearance {
  theme = $state<Theme>('system');
  density = $state<Density>('comfortable');

  constructor() {
    const theme = read(THEME_KEY);
    if (theme === 'light' || theme === 'dark') this.theme = theme;
    if (read(DENSITY_KEY) === 'compact') this.density = 'compact';
    this.apply();
  }

  cycleTheme(): void {
    const next =
      THEME_ORDER[(THEME_ORDER.indexOf(this.theme) + 1) % THEME_ORDER.length] ?? 'system';
    this.theme = next;
    write(THEME_KEY, next);
    this.apply();
  }

  toggleDensity(): void {
    this.density = this.density === 'compact' ? 'comfortable' : 'compact';
    write(DENSITY_KEY, this.density);
    this.apply();
  }

  private apply(): void {
    const root = document.documentElement;
    if (this.theme === 'system') delete root.dataset.theme;
    else root.dataset.theme = this.theme;
    if (this.density === 'compact') root.dataset.density = 'compact';
    else delete root.dataset.density;
  }
}

export const appearance = new Appearance();
