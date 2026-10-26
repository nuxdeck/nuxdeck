<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onDestroy, onMount, tick, type Component } from 'svelte';
  import { inventory } from '../inventory.svelte';
  import { findSection, resolveRoute, router } from '../router.svelte';
  import Sidebar from '../ui/Sidebar.svelte';
  import TopBar from '../ui/TopBar.svelte';
  import AddHost from '../../routes/AddHost.svelte';
  import AuditLog from '../../routes/AuditLog.svelte';
  import Alerts from '../../routes/Alerts.svelte';
  import Checks from '../../routes/Checks.svelte';
  import ContainerPage from '../../routes/ContainerPage.svelte';
  import HostPage from '../../routes/HostPage.svelte';
  import Inventory from '../../routes/Inventory.svelte';
  import NotFound from '../../routes/NotFound.svelte';
  import Overview from '../../routes/Overview.svelte';
  import Settings from '../../routes/Settings.svelte';
  import StatusPages from '../../routes/StatusPages.svelte';

  const pages: Record<string, Component> = {
    '/': Overview,
    '/inventory': Inventory,
    '/checks': Checks,
    '/alerts': Alerts,
    '/status-pages': StatusPages,
    '/settings': Settings,
    '/audit': AuditLog,
  };

  const SIDEBAR_ID = 'main-nav';
  const SIDEBAR_KEY = 'nux.sidebar';

  function savedCollapsed(): boolean {
    try {
      const saved = window.localStorage.getItem(SIDEBAR_KEY);
      if (saved === 'collapsed') return true;
      if (saved === 'expanded') return false;
    } catch {
      /* storage unavailable */
    }
    return window.innerWidth < 768;
  }

  let collapsed = $state(savedCollapsed());
  let first = true;

  const route = $derived(resolveRoute(router.path));
  const Page = $derived(route.kind === 'section' ? (pages[route.path] ?? NotFound) : NotFound);
  const baseTitle = $derived(
    route.kind === 'section'
      ? findSection(route.path)?.title
      : route.kind === 'add-host'
        ? 'Add a host'
        : route.kind === 'host'
          ? 'Host'
          : route.kind === 'container'
            ? 'Container'
            : 'Page not found',
  );

  // The live inventory belongs to the signed-in shell: it loads once and every page reads it.
  onMount(() => inventory.start());
  onDestroy(() => inventory.stop());

  function toggleSidebar(): void {
    collapsed = !collapsed;
    try {
      window.localStorage.setItem(SIDEBAR_KEY, collapsed ? 'collapsed' : 'expanded');
    } catch {
      /* the choice lasts for this page view only */
    }
  }

  // Client-side navigation keeps the page, so tell assistive technology: update the title and
  // move focus to the new heading. Skipped on first load, where the browser does it.
  $effect(() => {
    const title = router.titleOverride ?? baseTitle ?? 'Page not found';
    document.title = `${title} · Nux Deck`;
    if (first) {
      first = false;
      return;
    }
    void tick().then(() => document.getElementById('page-title')?.focus());
  });

  function interceptLinks(event: MouseEvent): void {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const anchor = (event.target as Element | null)?.closest('a');
    if (!anchor || anchor.target || anchor.hasAttribute('download')) return;
    const url = new URL(anchor.href, window.location.href);
    if (url.origin !== window.location.origin) return;
    event.preventDefault();
    router.navigate(url.pathname);
  }
</script>

<svelte:window onclick={interceptLinks} />

<a class="skip-link" href="#main">Skip to main content</a>
<div class="shell">
  <TopBar sidebarId={SIDEBAR_ID} sidebarCollapsed={collapsed} onToggleSidebar={toggleSidebar} />
  <div class="body">
    <Sidebar id={SIDEBAR_ID} {collapsed} />
    <main id="main" tabindex="-1">
      {#if route.kind === 'add-host'}
        <AddHost />
      {:else if route.kind === 'host'}
        {#key route.id}<HostPage id={route.id} />{/key}
      {:else if route.kind === 'container'}
        {#key route.id}<ContainerPage id={route.id} />{/key}
      {:else}
        <Page />
      {/if}
    </main>
  </div>
</div>

<style>
  .shell {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  .body {
    display: flex;
    flex: 1;
    min-height: 0;
  }

  main {
    flex: 1;
    min-width: 0;
    padding: var(--space-6);
  }

  main:focus {
    outline: none;
  }

  .skip-link {
    position: absolute;
    left: var(--space-2);
    top: -100px;
    z-index: 10;
    padding: var(--space-2) var(--space-3);
    background: var(--color-accent);
    color: var(--color-accent-text);
    border-radius: var(--radius-1);
  }

  .skip-link:focus {
    top: var(--space-2);
  }
</style>
