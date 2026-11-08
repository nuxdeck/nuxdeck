<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  interface Props {
    id: string;
    label: string;
    value: string;
    error?: string;
    hint?: string;
    maxlength?: number;
    rows?: number;
    required?: boolean;
    disabled?: boolean;
  }

  let {
    id,
    label,
    value = $bindable(),
    error,
    hint,
    maxlength,
    rows = 4,
    required = false,
    disabled = false,
  }: Props = $props();

  const describedBy = $derived(
    [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined,
  );
</script>

<div class="field">
  <label for={id}
    >{label}{#if required}<span class="req" aria-hidden="true"> *</span>{/if}</label
  >
  <textarea
    {id}
    bind:value
    {rows}
    {maxlength}
    {disabled}
    aria-required={required ? 'true' : undefined}
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={describedBy}></textarea>
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

  textarea {
    min-height: var(--target-size);
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
    resize: vertical;
  }

  textarea[aria-invalid='true'] {
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
