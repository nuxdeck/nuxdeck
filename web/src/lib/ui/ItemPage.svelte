<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import EmptyState from './EmptyState.svelte';
  import Tabs from './Tabs.svelte';

  interface Props {
    /** Shown above the heading: where the reader came from. */
    crumbs: Snippet;
    title: string;
    /** Status and other facts that belong next to the heading. */
    badges: Snippet;
    /** The Overview tab. */
    overview: Snippet;
  }

  let { crumbs, title, badges, overview }: Props = $props();

  // The item page is the anchor of the product (docs/06-ux.md): every tab exists from the start so the
  // layout and the links to it are stable; the tabs whose data does not exist yet say so.
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'metrics', label: 'Metrics' },
    { id: 'logs', label: 'Logs' },
    { id: 'checks', label: 'Checks' },
    { id: 'alerts', label: 'Alerts' },
    { id: 'activity', label: 'Activity' },
  ];
  const soon: Record<string, string> = {
    metrics: 'Charts for CPU, memory, disk and network are not available in this version yet.',
    logs: 'Live logs are not available in this version yet.',
    checks: 'Uptime checks that target this item are not available in this version yet.',
    alerts: 'Alerts for this item are not available in this version yet.',
    activity: 'The history of changes to this item is not available in this version yet.',
  };

  let selected = $state('overview');
</script>

<nav class="crumbs" aria-label="Breadcrumb">{@render crumbs()}</nav>
<div class="head">
  <h1 id="page-title" tabindex="-1">{title}</h1>
  <div class="badges">{@render badges()}</div>
</div>
<p class="meta">Tags: none yet · Owner: not set</p>

<Tabs {tabs} label="{title} sections" {selected} onselect={(id) => (selected = id)}>
  {#snippet panel(id)}
    {#if id === 'overview'}
      {@render overview()}
    {:else}
      <EmptyState title={tabs.find((t) => t.id === id)?.label ?? id}>{soon[id]}</EmptyState>
    {/if}
  {/snippet}
</Tabs>

<style>
  .crumbs {
    margin-bottom: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }

  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
    overflow-wrap: anywhere;
  }

  h1:focus {
    outline: none;
  }

  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .meta {
    margin-top: var(--space-1);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }
</style>
