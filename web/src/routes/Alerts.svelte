<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import AlertList from '../lib/alerts/AlertList.svelte';
  import ChannelsView from '../lib/alerts/ChannelsView.svelte';
  import { isAdmin } from '../lib/alerts/model';
  import RoutesView from '../lib/alerts/RoutesView.svelte';
  import RulesView from '../lib/alerts/RulesView.svelte';
  import SilencesView from '../lib/alerts/SilencesView.svelte';
  import { findSection, router, type AlertsView } from '../lib/router.svelte';

  let { view = 'alerts' }: { view?: AlertsView } = $props();

  const section = findSection('/alerts');
  const admin = $derived(isAdmin());

  const links = $derived([
    { view: 'alerts', href: '/alerts', label: 'Alerts' },
    { view: 'rules', href: '/alerts/rules', label: 'Rules' },
    { view: 'silences', href: '/alerts/silences', label: 'Silences' },
    { view: 'channels', href: '/alerts/channels', label: 'Channels' },
    { view: 'routes', href: '/alerts/routes', label: 'Routes' },
  ]);

  const subtitles: Record<AlertsView, string> = {
    alerts: 'What fired and who is handling it?',
    rules: 'When should an alert open?',
    silences: 'What is muted, and until when?',
    channels: 'Where do notifications go?',
    routes: 'Which alert goes to which channel?',
  };

  $effect(() => {
    router.titleOverride =
      view === 'alerts' ? null : `${links.find((l) => l.view === view)?.label} · Alerts`;
  });
</script>

<div class="head">
  <h1 id="page-title" tabindex="-1">{section?.title}</h1>
  <p class="question">{subtitles[view]}</p>
</div>

<nav class="subnav" aria-label="Alerts sections">
  <ul>
    {#each links as l (l.view)}
      <li>
        <a href={l.href} aria-current={view === l.view ? 'page' : undefined}>{l.label}</a>
        {#if (l.view === 'channels' || l.view === 'routes') && !admin}
          <span class="visually-hidden"> (administrators only)</span>
        {/if}
      </li>
    {/each}
  </ul>
</nav>

{#if view === 'alerts'}
  <AlertList />
{:else if view === 'rules'}
  <RulesView />
{:else if view === 'silences'}
  <SilencesView />
{:else if view === 'channels'}
  <ChannelsView />
{:else}
  <RoutesView />
{/if}

<style>
  .head {
    margin-bottom: var(--space-3);
  }

  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  .question {
    margin: var(--space-1) 0 0;
    color: var(--color-text-muted);
  }

  .subnav ul {
    display: flex;
    gap: var(--space-1);
    margin: 0 0 var(--space-4);
    padding: 0;
    border-bottom: 1px solid var(--color-border);
    list-style: none;
    overflow-x: auto;
  }

  .subnav a {
    display: inline-flex;
    align-items: center;
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    border-bottom: 2px solid transparent;
    color: var(--color-text-muted);
    font-weight: 600;
    text-decoration: none;
    white-space: nowrap;
  }

  .subnav a[aria-current='page'] {
    border-bottom-color: var(--color-accent);
    color: var(--color-text);
  }
</style>
