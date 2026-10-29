<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    children?: Snippet;
    /** The next step as a button or link, so the empty state is also the way forward (docs/06-ux.md). */
    action?: Snippet;
  }

  let { title, children, action }: Props = $props();
</script>

<section class="empty" aria-label={title}>
  <h2>{title}</h2>
  {#if children}
    <p>{@render children()}</p>
  {/if}
  {#if action}
    <div class="action">{@render action()}</div>
  {/if}
</section>

<style>
  .empty {
    max-width: 56ch;
    padding: var(--space-6);
    border: 1px dashed var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
  }

  h2 {
    font-size: var(--font-size-md);
    margin-bottom: var(--space-2);
  }

  p {
    color: var(--color-text-muted);
  }

  .action {
    margin-top: var(--space-4);
  }
</style>
