<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { auth } from '../auth.svelte';
  import { palette } from '../palette.svelte';
  import { appearance } from '../theme.svelte';
  import Icon from './Icon.svelte';

  interface Props {
    sidebarId: string;
    sidebarCollapsed: boolean;
    onToggleSidebar: () => void;
  }

  let { sidebarId, sidebarCollapsed, onToggleSidebar }: Props = $props();

  const themeIcon = $derived(
    appearance.theme === 'light' ? 'sun' : appearance.theme === 'dark' ? 'moon' : 'monitor',
  );
</script>

<header class="topbar">
  <button
    type="button"
    class="icon-button"
    aria-controls={sidebarId}
    aria-expanded={!sidebarCollapsed}
    aria-label="Toggle sidebar"
    onclick={onToggleSidebar}
  >
    <Icon name="panelLeft" />
  </button>
  <a class="brand" href="/">Nux Deck</a>
  <span class="spacer"></span>
  <button
    type="button"
    class="text-button search"
    aria-haspopup="dialog"
    onclick={() => palette.open()}
  >
    <Icon name="search" size={16} />
    Search
    <kbd>Ctrl K</kbd>
  </button>
  {#if auth.user}
    <span class="user">{auth.user.name}</span>
    <button type="button" class="text-button" onclick={() => void auth.logout()}>Sign out</button>
  {/if}
  <button
    type="button"
    class="icon-button"
    aria-label={`Row density: ${appearance.density}. Switch`}
    onclick={() => appearance.toggleDensity()}
  >
    <Icon name={appearance.density === 'compact' ? 'rows4' : 'rows3'} />
  </button>
  <button
    type="button"
    class="icon-button"
    aria-label={`Theme: ${appearance.theme}. Switch`}
    onclick={() => appearance.cycleTheme()}
  >
    <Icon name={themeIcon} />
  </button>
</header>

<style>
  .topbar {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    height: var(--topbar-height);
    padding: 0 var(--space-3);
    border-bottom: 1px solid var(--color-border);
    background: var(--color-surface);
  }

  .brand {
    font-size: var(--font-size-md);
    font-weight: 700;
    color: var(--color-text);
    text-decoration: none;
  }

  .spacer {
    flex: 1;
  }

  .user {
    color: var(--color-text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 16ch;
  }

  .text-button {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    cursor: pointer;
  }

  .text-button:hover {
    background: var(--color-surface-sunken);
  }

  .search {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }

  kbd {
    padding: 0 var(--space-1);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    color: var(--color-text-muted);
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }

  .icon-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: var(--target-size);
    min-height: var(--target-size);
    border: 1px solid transparent;
    border-radius: var(--radius-1);
    background: transparent;
    cursor: pointer;
  }

  .icon-button:hover {
    background: var(--color-surface-sunken);
    border-color: var(--color-border);
  }
</style>
