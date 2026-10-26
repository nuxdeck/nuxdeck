<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Tab {
    id: string;
    label: string;
  }

  interface Props {
    tabs: Tab[];
    /** Accessible name of the tab list. */
    label: string;
    selected: string;
    onselect: (id: string) => void;
    panel: Snippet<[string]>;
  }

  let { tabs, label, selected, onselect, panel }: Props = $props();

  // WAI-ARIA tabs pattern: arrow keys move between tabs (and select them), Home and End jump to the ends,
  // and only the selected tab is in the page's tab order.
  function onkeydown(event: KeyboardEvent, index: number): void {
    const last = tabs.length - 1;
    const target =
      event.key === 'ArrowRight'
        ? (index + 1) % tabs.length
        : event.key === 'ArrowLeft'
          ? (index - 1 + tabs.length) % tabs.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : -1;
    if (target < 0) return;
    event.preventDefault();
    const next = tabs[target];
    if (!next) return;
    onselect(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  }
</script>

<div class="tabs" role="tablist" aria-label={label}>
  {#each tabs as tab, i (tab.id)}
    <button
      type="button"
      role="tab"
      id="tab-{tab.id}"
      aria-selected={tab.id === selected}
      aria-controls="panel-{tab.id}"
      tabindex={tab.id === selected ? 0 : -1}
      onclick={() => onselect(tab.id)}
      onkeydown={(e) => onkeydown(e, i)}
    >
      {tab.label}
    </button>
  {/each}
</div>
{#each tabs as tab (tab.id)}
  <div
    role="tabpanel"
    id="panel-{tab.id}"
    aria-labelledby="tab-{tab.id}"
    tabindex="0"
    hidden={tab.id !== selected}
  >
    {#if tab.id === selected}
      {@render panel(tab.id)}
    {/if}
  </div>
{/each}

<style>
  .tabs {
    display: flex;
    gap: var(--space-1);
    margin: var(--space-4) 0;
    border-bottom: 1px solid var(--color-border);
    overflow-x: auto;
  }

  button {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    border: 0;
    border-bottom: 2px solid transparent;
    background: none;
    color: var(--color-text-muted);
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }

  button[aria-selected='true'] {
    border-bottom-color: var(--color-accent);
    color: var(--color-text);
  }

  [role='tabpanel'] {
    min-width: 0;
  }
</style>
