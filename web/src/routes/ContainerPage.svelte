<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { api, ApiRequestError, type Container } from '../lib/api/client';
  import { formatPort, formatTime } from '../lib/format';
  import { inventory } from '../lib/inventory.svelte';
  import { router } from '../lib/router.svelte';
  import ItemPage from '../lib/ui/ItemPage.svelte';
  import NotFoundItem from '../lib/ui/NotFoundItem.svelte';
  import StatusBadge from '../lib/ui/StatusBadge.svelte';

  let { id }: { id: string } = $props();

  let fetched = $state<Container | null>(null);
  let missing = $state(false);
  const container = $derived(inventory.container(id) ?? (fetched?.id === id ? fetched : null));

  $effect(() => {
    if (!inventory.loaded || inventory.container(id) || fetched?.id === id) return;
    missing = false;
    api
      .container(id)
      .then((c) => (fetched = c))
      .catch((e) => {
        if (e instanceof ApiRequestError && e.error.status === 404) missing = true;
      });
  });

  $effect(() => {
    router.titleOverride = container?.name ?? null;
  });

  const host = $derived(container ? inventory.host(container.host_id) : undefined);
  const labels = $derived(
    Object.entries(container?.labels ?? {}).sort(([a], [b]) => a.localeCompare(b)),
  );
</script>

{#if container}
  <ItemPage title={container.name}>
    {#snippet crumbs()}<a href="/inventory">Inventory</a> / Container{/snippet}
    {#snippet badges()}
      <StatusBadge status={container.state} />
      {#if container.gone_at}<StatusBadge status="gone" />{/if}
    {/snippet}
    {#snippet overview()}
      <dl class="facts">
        <dt>Host</dt>
        <dd>
          <a href="/inventory/hosts/{container.host_id}">{host?.hostname ?? 'Unknown host'}</a>
        </dd>
        <dt>Image</dt>
        <dd class="mono">{container.image}</dd>
        <dt>Runtime</dt>
        <dd>{container.runtime === 'podman' ? 'Podman' : 'Docker'}</dd>
        <dt>Runtime ID</dt>
        <dd class="mono">{container.runtime_id}</dd>
        <dt>Created</dt>
        <dd>{formatTime(container.created_at)}</dd>
        <dt>Restarts</dt>
        <dd>{container.restart_count}</dd>
        {#if container.gone_at}
          <dt>Removed</dt>
          <dd>{formatTime(container.gone_at)}</dd>
        {/if}
      </dl>

      <h2>Published ports</h2>
      {#if container.ports.length === 0}
        <p class="muted">No ports are published.</p>
      {:else}
        <ul class="ports mono">
          {#each container.ports as p (formatPort(p))}
            <li>{formatPort(p)}</li>
          {/each}
        </ul>
      {/if}

      <h2>Labels</h2>
      {#if labels.length === 0}
        <p class="muted">No labels.</p>
      {:else}
        <div class="table-wrap">
          <table class="data-table">
            <caption class="visually-hidden">Labels</caption>
            <thead>
              <tr><th scope="col">Key</th><th scope="col">Value</th></tr>
            </thead>
            <tbody>
              {#each labels as [key, value] (key)}
                <tr>
                  <th scope="row" class="mono">{key}</th>
                  <td class="mono">{value}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <p class="muted note">
          Values that look like secrets are redacted on the host before they reach the server.
        </p>
      {/if}
    {/snippet}
  </ItemPage>
{:else if missing}
  <NotFoundItem what="container" />
{:else}
  <h1 id="page-title" tabindex="-1">Container</h1>
  <p role="status">Loading…</p>
{/if}

<style>
  h1:focus {
    outline: none;
  }

  h2 {
    margin: var(--space-6) 0 var(--space-2);
    font-size: var(--font-size-md);
  }

  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-2) var(--space-6);
    margin: 0;
  }

  dt {
    color: var(--color-text-muted);
    font-weight: 600;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .ports {
    margin: 0;
    padding-left: var(--space-6);
  }

  .muted {
    color: var(--color-text-muted);
  }

  .note {
    margin-top: var(--space-2);
    font-size: var(--font-size-sm);
  }
</style>
