<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { MAX_SELECTOR_ITEMS, tagError } from './model';

  interface Props {
    id: string;
    label: string;
    tags: string[];
    hint?: string;
    error?: string;
    disabled?: boolean;
  }

  let { id, label, tags = $bindable(), hint, error, disabled = false }: Props = $props();

  let draft = $state('');
  let problem = $state('');
  let announce = $state('');

  const shownError = $derived(problem || error);
  const describedBy = $derived(
    [`${id}-hint`, shownError ? `${id}-error` : ''].filter(Boolean).join(' '),
  );

  function add(): void {
    const value = draft.trim();
    if (value === '') return;
    const bad = tagError(value);
    if (bad) {
      problem = bad;
      return;
    }
    if (tags.includes(value)) {
      problem = `"${value}" is already in the list.`;
      return;
    }
    if (tags.length >= MAX_SELECTOR_ITEMS) {
      problem = 'Use at most 50 tags.';
      return;
    }
    tags.push(value);
    announce = `Added ${value}`;
    draft = '';
    problem = '';
  }

  function remove(i: number): void {
    const [gone] = tags.splice(i, 1);
    announce = `Removed ${gone}`;
    document.getElementById(id)?.focus();
  }

  function onkeydown(event: KeyboardEvent): void {
    // Enter adds the chip instead of submitting the surrounding form.
    if (event.key !== 'Enter') return;
    event.preventDefault();
    add();
  }
</script>

<div class="chips">
  <label for={id}>{label}</label>
  <div class="row">
    <input
      {id}
      bind:value={draft}
      {disabled}
      {onkeydown}
      class="mono"
      placeholder="env:production"
      autocomplete="off"
      spellcheck="false"
      autocapitalize="off"
      aria-invalid={shownError ? 'true' : undefined}
      aria-describedby={describedBy}
    />
    <button type="button" class="add" {disabled} onclick={add} aria-label="Add {label}">Add</button>
  </div>
  <p id="{id}-hint" class="hint">
    {hint ?? 'Press Enter or Add. Use key:value, or just key to match any value.'}
  </p>
  {#if shownError}<p id="{id}-error" class="error">{shownError}</p>{/if}
  {#if tags.length > 0}
    <ul aria-label="{label}, added">
      {#each tags as tag, i (tag)}
        <li class="mono">
          {tag}
          <button type="button" {disabled} aria-label="Remove {tag}" onclick={() => remove(i)}
            >Remove</button
          >
        </li>
      {/each}
    </ul>
  {/if}
  <p class="visually-hidden" role="status">{announce}</p>
</div>

<style>
  .chips {
    display: grid;
    gap: var(--space-1);
    min-width: 0;
  }

  label {
    font-weight: 600;
  }

  .row {
    display: flex;
    gap: var(--space-2);
  }

  input {
    flex: 1;
    min-width: 0;
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  input[aria-invalid='true'] {
    border-color: var(--color-status-critical);
  }

  .add {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font-weight: 600;
    cursor: pointer;
  }

  ul {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    padding: 0 0 0 var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    font-size: var(--font-size-sm);
  }

  li button {
    min-height: var(--target-size);
    padding: 0 var(--space-2);
    border: 0;
    background: none;
    color: var(--color-accent);
    cursor: pointer;
    font: inherit;
    text-decoration: underline;
  }

  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .error {
    margin: 0;
    color: var(--color-status-critical);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }
</style>
