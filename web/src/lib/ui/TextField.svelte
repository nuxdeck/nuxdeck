<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props {
    id: string;
    label: string;
    value: string;
    error?: string;
    hint?: string;
    placeholder?: string;
    inputmode?: HTMLInputAttributes['inputmode'];
    maxlength?: number;
    /** Marks the field as mandatory for assistive technology; validation itself is ours, not the browser's. */
    required?: boolean;
    mono?: boolean;
    disabled?: boolean;
    type?: 'text' | 'password';
    autocomplete?: HTMLInputAttributes['autocomplete'];
  }

  let {
    id,
    label,
    value = $bindable(),
    error,
    hint,
    placeholder,
    inputmode,
    maxlength,
    required = false,
    mono = false,
    disabled = false,
    type = 'text',
    autocomplete = 'off',
  }: Props = $props();

  const describedBy = $derived(
    [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined,
  );
</script>

<div class="field">
  <label for={id}
    >{label}{#if required}<span class="req" aria-hidden="true"> *</span>{/if}</label
  >
  <input
    {id}
    {type}
    bind:value
    {placeholder}
    {inputmode}
    {maxlength}
    {disabled}
    {autocomplete}
    class:mono
    aria-required={required ? 'true' : undefined}
    spellcheck="false"
    autocapitalize="off"
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={describedBy}
  />
  {#if hint}<p id="{id}-hint" class="hint">{hint}</p>{/if}
  {#if error}<p id="{id}-error" class="error">{error}</p>{/if}
</div>

<style>
  .field {
    display: grid;
    gap: var(--space-1);
    min-width: 0;
  }

  label {
    font-weight: 600;
  }

  input {
    min-height: var(--target-size);
    min-width: 0;
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  input.mono {
    font-family: var(--font-mono);
  }

  input[aria-invalid='true'] {
    border-color: var(--color-status-critical);
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
