<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  interface Props {
    id: string;
    label: string;
    checked: boolean;
    hint?: string;
    disabled?: boolean;
    onchange?: () => void;
  }

  let { id, label, checked = $bindable(), hint, disabled = false, onchange }: Props = $props();
</script>

<div class="toggle">
  <input
    {id}
    type="checkbox"
    bind:checked
    {disabled}
    {onchange}
    aria-describedby={hint ? `${id}-hint` : undefined}
  />
  <div>
    <label for={id}>{label}</label>
    {#if hint}<p id="{id}-hint" class="hint">{hint}</p>{/if}
  </div>
</div>

<style>
  .toggle {
    display: flex;
    gap: var(--space-2);
    align-items: flex-start;
  }

  input {
    flex: none;
    width: 1.25rem;
    height: 1.25rem;
    margin-top: 0.15rem;
  }

  label {
    font-weight: 600;
  }

  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }
</style>
