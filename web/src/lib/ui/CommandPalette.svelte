<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import { api, ApiRequestError, type SearchHit } from '../api/client';
  import { palette } from '../palette.svelte';
  import { router } from '../router.svelte';
  import Icon from './Icon.svelte';
  import StatusBadge from './StatusBadge.svelte';

  const DEBOUNCE_MS = 150;
  const MAX_QUERY = 64;

  let query = $state('');
  let hits = $state<SearchHit[]>([]);
  let active = $state(0);
  let phase = $state<'idle' | 'loading' | 'done' | 'failed'>('idle');
  let input = $state<HTMLInputElement | null>(null);
  let dialog = $state<HTMLDivElement | null>(null);

  let opener: HTMLElement | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let controller: AbortController | undefined;

  const listId = 'palette-results';
  const optionId = (i: number) => `palette-option-${i}`;

  // Focus moves into the dialog when it opens and returns to where the reader was when it closes.
  $effect(() => {
    if (!palette.isOpen) return;
    opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    void tick().then(() => input?.focus());
    return () => {
      clearTimeout(timer);
      controller?.abort();
      query = '';
      hits = [];
      active = 0;
      phase = 'idle';
      opener?.focus();
      opener = null;
    };
  });

  onDestroy(() => {
    clearTimeout(timer);
    controller?.abort();
  });

  function onInput(): void {
    clearTimeout(timer);
    controller?.abort();
    const q = query.trim();
    if (!q) {
      hits = [];
      phase = 'idle';
      return;
    }
    phase = 'loading';
    timer = setTimeout(() => void run(q), DEBOUNCE_MS);
  }

  async function run(q: string): Promise<void> {
    controller = new AbortController();
    const mine = controller;
    try {
      const found = await api.search(q, mine.signal);
      if (mine.signal.aborted) return;
      hits = found;
      active = 0;
      phase = 'done';
    } catch (e) {
      if (mine.signal.aborted) return;
      hits = [];
      phase = 'failed';
      if (!(e instanceof ApiRequestError)) throw e;
    }
  }

  function go(hit: SearchHit): void {
    palette.close();
    router.navigate(`/inventory/${hit.type === 'host' ? 'hosts' : 'containers'}/${hit.id}`);
  }

  function move(delta: number): void {
    if (hits.length === 0) return;
    active = (active + delta + hits.length) % hits.length;
    void tick().then(() =>
      document.getElementById(optionId(active))?.scrollIntoView?.({ block: 'nearest' }),
    );
  }

  function onKeydown(e: KeyboardEvent): void {
    switch (e.key) {
      case 'Escape':
        e.preventDefault();
        palette.close();
        return;
      case 'ArrowDown':
        e.preventDefault();
        move(1);
        return;
      case 'ArrowUp':
        e.preventDefault();
        move(-1);
        return;
      case 'Home':
      case 'End':
        // In a combobox these keys move the caret in the text field.
        return;
      case 'Enter': {
        const hit = hits[active];
        if (hit && phase === 'done') {
          e.preventDefault();
          go(hit);
        }
        return;
      }
      case 'Tab':
        trapFocus(e);
        return;
    }
  }

  // Focus stays inside the dialog while it is open (WCAG 2.4.3, dialog pattern).
  function trapFocus(e: KeyboardEvent): void {
    const items = [...(dialog?.querySelectorAll<HTMLElement>('input, button') ?? [])];
    const first = items[0];
    const last = items.at(-1);
    if (!first || !last) return;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

  const status = $derived(
    phase === 'loading'
      ? 'Searching…'
      : phase === 'failed'
        ? 'Search is unavailable. Try again.'
        : phase === 'done'
          ? hits.length === 0
            ? 'No results'
            : `${hits.length} ${hits.length === 1 ? 'result' : 'results'}`
          : '',
  );

  const matchLabel = (h: SearchHit): string =>
    h.match === 'name' ? '' : `${h.match === 'tag' ? 'Tag' : 'Address'} ${h.detail}`;
</script>

{#if palette.isOpen}
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="backdrop" onclick={() => palette.close()}>
    <div
      class="dialog"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      tabindex="-1"
      bind:this={dialog}
      onclick={(e) => e.stopPropagation()}
      onkeydown={onKeydown}
    >
      <div class="search">
        <Icon name="search" size={16} />
        <label class="visually-hidden" for="palette-input">Search hosts and containers</label>
        <input
          id="palette-input"
          bind:this={input}
          bind:value={query}
          oninput={onInput}
          type="text"
          role="combobox"
          aria-expanded={hits.length > 0}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={hits.length > 0 ? optionId(active) : undefined}
          placeholder="Search by name, tag or IP"
          maxlength={MAX_QUERY}
          autocomplete="off"
          spellcheck="false"
        />
        <button type="button" class="close" onclick={() => palette.close()}>Close</button>
      </div>
      <ul id={listId} role="listbox" aria-label="Results">
        {#each hits as h, i (h.type + h.id)}
          <!-- Options are driven from the combobox; the pointer is a second way in. -->
          <!-- svelte-ignore a11y_click_events_have_key_events -->
          <li
            id={optionId(i)}
            role="option"
            aria-selected={i === active}
            class:active={i === active}
            onclick={() => go(h)}
            onmousemove={() => (active = i)}
          >
            <span class="kind">{h.type === 'host' ? 'Host' : 'Container'}</span>
            <span class="name">{h.name}</span>
            {#if h.host}<span class="muted">on {h.host}</span>{/if}
            {#if matchLabel(h)}<span class="muted mono">{matchLabel(h)}</span>{/if}
            <span class="badge"><StatusBadge status={h.status} /></span>
          </li>
        {/each}
      </ul>
      <p class="hint" role="status">
        {#if status}{status}{:else}Type a host, container, tag or IP address.{/if}
      </p>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 50;
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding: 12vh var(--space-4) var(--space-4);
    background: var(--color-scrim);
  }

  .dialog {
    width: min(40rem, 100%);
    max-height: 70vh;
    overflow: auto;
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-2);
    background: var(--color-surface);
    color: var(--color-text);
    box-shadow: var(--shadow-dialog);
  }

  .dialog:focus {
    outline: none;
  }

  .search {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--color-border);
  }

  input {
    flex: 1;
    min-width: 0;
    min-height: var(--target-size);
    border: 0;
    background: transparent;
    color: var(--color-text);
    font: inherit;
  }

  .close {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    cursor: pointer;
  }

  ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    cursor: pointer;
  }

  li.active {
    background: var(--color-surface-sunken);
    outline: 2px solid var(--color-accent);
    outline-offset: -2px;
  }

  .kind {
    min-width: 5.5rem;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .name {
    font-weight: 600;
  }

  .muted {
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .badge {
    margin-left: auto;
  }

  .hint {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-top: 1px solid var(--color-border);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }
</style>
