<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { SecretDraft } from './form';

  interface Props {
    id: string;
    label: string;
    draft: SecretDraft;
    error?: string;
    /** Hides the visible label when the surrounding row already names the field. */
    hideLabel?: boolean;
  }

  let { id, label, draft = $bindable(), error, hideLabel = false }: Props = $props();

  const describedBy = $derived(
    [`${id}-state`, error ? `${id}-error` : ''].filter(Boolean).join(' '),
  );
  const placeholder = $derived(draft.wasSet ? 'Set — leave blank to keep' : 'Not set');
</script>

<!-- A stored secret is never sent to the browser; only whether it exists is shown. -->
<div class="secret">
  <label for={id} class:visually-hidden={hideLabel}>{label}</label>
  <div class="row">
    <input
      {id}
      type="password"
      bind:value={draft.input}
      {placeholder}
      autocomplete="new-password"
      spellcheck="false"
      disabled={draft.clear}
      aria-invalid={error ? 'true' : undefined}
      aria-describedby={describedBy}
    />
    {#if draft.wasSet && !draft.clear}
      <button
        type="button"
        class="link"
        aria-label="Clear stored {label}"
        onclick={() => ((draft.clear = true), (draft.input = ''))}>Clear</button
      >
    {:else if draft.clear}
      <button
        type="button"
        class="link"
        aria-label="Keep stored {label}"
        onclick={() => (draft.clear = false)}>Keep</button
      >
    {/if}
  </div>
  <p id="{id}-state" class="hint">
    {#if draft.clear}
      The stored value will be removed when you save.
    {:else if draft.input !== ''}
      A new value will replace the stored one when you save.
    {:else if draft.wasSet}
      A value is set. It is write-only and cannot be shown.
    {:else}
      No value is set.
    {/if}
  </p>
  {#if error}<p id="{id}-error" class="error">{error}</p>{/if}
</div>

<style>
  .secret {
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
    align-items: center;
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

  .link {
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
