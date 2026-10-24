// SPDX-License-Identifier: AGPL-3.0-only
try {
  var root = document.documentElement;
  var theme = localStorage.getItem('nux.theme');
  var density = localStorage.getItem('nux.density');
  if (theme === 'light' || theme === 'dark') root.dataset.theme = theme;
  if (density === 'compact') root.dataset.density = density;
} catch {
  /* storage unavailable: fall back to the OS theme */
}
