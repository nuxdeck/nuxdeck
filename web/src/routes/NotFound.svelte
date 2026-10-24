<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import EmptyState from '../lib/ui/EmptyState.svelte';
</script>

<h1 id="page-title" tabindex="-1">Page not found</h1>
<EmptyState title="This page does not exist">
  Pick a section from the sidebar, or go back to the <a href="/">Overview</a>.
</EmptyState>

<style>
  h1 {
    font-size: var(--font-size-xl);
    margin-bottom: var(--space-4);
  }

  h1:focus {
    outline: none;
  }
</style>
