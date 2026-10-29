<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { tagText, type Tags } from '../tags';

  let { tags }: { tags: Tags } = $props();
  const chips = $derived(tagText(tags));
</script>

{#if chips.length === 0}
  <span class="none">—</span>
{:else}
  <ul>
    {#each chips as chip (chip)}<li class="mono">{chip}</li>{/each}
  </ul>
{/if}

<style>
  ul {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
    font-size: var(--font-size-sm);
  }
</style>
