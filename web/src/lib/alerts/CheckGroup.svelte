<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  interface Props {
    id: string;
    legend: string;
    options: readonly { value: string; label: string }[];
    selected: string[];
    hint?: string;
    disabled?: boolean;
  }

  let { id, legend, options, selected = $bindable(), hint, disabled = false }: Props = $props();

  function toggle(value: string, on: boolean): void {
    if (on && !selected.includes(value)) selected.push(value);
    if (!on) selected.splice(0, selected.length, ...selected.filter((v) => v !== value));
  }
</script>

<fieldset aria-describedby={hint ? `${id}-hint` : undefined}>
  <legend>{legend}</legend>
  {#if hint}<p id="{id}-hint" class="hint">{hint}</p>{/if}
  <div class="options">
    {#each options as o (o.value)}
      <label>
        <input
          type="checkbox"
          {disabled}
          checked={selected.includes(o.value)}
          onchange={(e) => toggle(o.value, e.currentTarget.checked)}
        />
        {o.label}
      </label>
    {/each}
  </div>
</fieldset>

<style>
  fieldset {
    margin: 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }

  legend {
    padding: 0;
    font-weight: 600;
  }

  .options {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1) var(--space-4);
  }

  label {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--target-size);
  }

  input {
    width: 1.25rem;
    height: 1.25rem;
  }

  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }
</style>
