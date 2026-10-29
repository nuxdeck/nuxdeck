// SPDX-License-Identifier: AGPL-3.0-only

/** Whether the command palette is open (docs/06-ux.md, Command palette). */
class PaletteState {
  isOpen = $state(false);

  open(): void {
    this.isOpen = true;
  }

  close(): void {
    this.isOpen = false;
  }

  toggle(): void {
    this.isOpen = !this.isOpen;
  }
}

export const palette = new PaletteState();

/** True for Ctrl+K and Cmd+K, the shortcut that opens the palette. */
export function isPaletteShortcut(e: KeyboardEvent): boolean {
  return (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k';
}
