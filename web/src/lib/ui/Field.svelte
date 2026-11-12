<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props {
    id: string;
    label: string;
    value: string;
    type?: 'text' | 'email' | 'password';
    error?: string;
    hint?: string;
    autocomplete?: HTMLInputAttributes['autocomplete'];
    disabled?: boolean;
  }

  let {
    id,
    label,
    value = $bindable(),
    type = 'text',
    error,
    hint,
    autocomplete,
    disabled = false,
  }: Props = $props();

  const describedBy = $derived(
    [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined,
  );
</script>

<div class="field">
  <label for={id}>{label}</label>
  <input
    {id}
    {type}
    bind:value
    {autocomplete}
    {disabled}
    required
    spellcheck="false"
    autocapitalize="off"
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={describedBy}
  />
  {#if hint}
    <p id="{id}-hint" class="hint">{hint}</p>
  {/if}
  {#if error}
    <p id="{id}-error" class="error" role="alert">{error}</p>
  {/if}
</div>

<style>
  .field {
    display: grid;
    gap: var(--space-1);
  }

  label {
    font-weight: 600;
  }

  input {
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

  .hint {
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .error {
    color: var(--color-status-critical);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }
</style>
