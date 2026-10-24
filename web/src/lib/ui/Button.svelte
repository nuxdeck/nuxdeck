<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    type?: 'button' | 'submit';
    variant?: 'primary' | 'secondary';
    disabled?: boolean;
    onclick?: () => void;
    children: Snippet;
  }

  let {
    type = 'button',
    variant = 'primary',
    disabled = false,
    onclick,
    children,
  }: Props = $props();
</script>

<button {type} class={variant} {disabled} {onclick}>
  {@render children()}
</button>

<style>
  button {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-4);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    font-weight: 600;
    cursor: pointer;
  }

  .primary {
    background: var(--color-accent);
    border-color: var(--color-accent);
    color: var(--color-accent-text);
  }

  .secondary {
    background: var(--color-surface);
    color: var(--color-text);
  }

  button:disabled {
    cursor: progress;
    opacity: 0.7;
  }
</style>
