<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import EmptyState from './EmptyState.svelte';

  let { what }: { what: 'host' | 'container' } = $props();
</script>

<h1 id="page-title" tabindex="-1">{what === 'host' ? 'Host' : 'Container'} not found</h1>
<EmptyState title="Nothing here">
  This {what} does not exist, or it was removed. Go back to the <a href="/inventory">inventory</a>.
</EmptyState>

<style>
  h1 {
    margin-bottom: var(--space-4);
    font-size: var(--font-size-xl);
  }

  h1:focus {
    outline: none;
  }
</style>
