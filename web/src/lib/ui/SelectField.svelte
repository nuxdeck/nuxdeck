<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  interface Props {
    id: string;
    label: string;
    value: string;
    options: readonly { value: string; label: string }[];
    error?: string;
    hint?: string;
    disabled?: boolean;
    onchange?: () => void;
  }

  let {
    id,
    label,
    value = $bindable(),
    options,
    error,
    hint,
    disabled = false,
    onchange,
  }: Props = $props();

  const describedBy = $derived(
    [hint ? `${id}-hint` : '', error ? `${id}-error` : ''].filter(Boolean).join(' ') || undefined,
  );
</script>

<div class="field">
  <label for={id}>{label}</label>
  <select
    {id}
    bind:value
    {disabled}
    {onchange}
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={describedBy}
  >
    {#each options as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
  </select>
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

  select {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  select[aria-invalid='true'] {
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
