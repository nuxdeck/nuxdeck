<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  interface Props {
    title: string;
    children?: import('svelte').Snippet;
  }

  let { title, children }: Props = $props();
</script>

<section class="empty" aria-label={title}>
  <h2>{title}</h2>
  {#if children}
    <p>{@render children()}</p>
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
</style>
