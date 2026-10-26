<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { api, ApiRequestError, type Host } from '../lib/api/client';
  import { bootTimeISO, formatBytes, formatTime, parseDisks } from '../lib/format';
  import { inventory } from '../lib/inventory.svelte';
  import { router } from '../lib/router.svelte';
  import JournalLogs from '../lib/ui/JournalLogs.svelte';
  import ItemPage from '../lib/ui/ItemPage.svelte';
  import NotFoundItem from '../lib/ui/NotFoundItem.svelte';
  import StatusBadge from '../lib/ui/StatusBadge.svelte';

  let { id }: { id: string } = $props();

  // Live hosts come from the store; a host that is gone (not in the list) is fetched once.
  let fetched = $state<Host | null>(null);
  let missing = $state(false);
  const host = $derived(inventory.host(id) ?? (fetched?.id === id ? fetched : null));

  $effect(() => {
    if (!inventory.loaded || inventory.host(id) || fetched?.id === id) return;
    missing = false;
    api
      .host(id)
      .then((h) => (fetched = h))
      .catch((e) => {
        if (e instanceof ApiRequestError && e.error.status === 404) missing = true;
      });
  });

  $effect(() => {
    router.titleOverride = host?.hostname ?? null;
  });

  const containers = $derived(inventory.containersOf(id));
  const disks = $derived(parseDisks(host?.facts.disks));
  const booted = $derived(host ? bootTimeISO(host.facts) : null);
</script>

{#if host}
  <ItemPage
    title={host.hostname}
    item={{ kind: 'hosts', id: host.id, owner: host.owner, tags: host.tags, etag: host.etag }}
    cpuCount={host.cpu_count}
  >
    {#snippet crumbs()}<a href="/inventory">Inventory</a> / Host{/snippet}
    {#snippet badges()}<StatusBadge status={host.status} />{/snippet}
    {#snippet overview()}
      <dl class="facts">
        <dt>System</dt>
        <dd>{host.distro || host.os} ({host.arch})</dd>
        <dt>Kernel</dt>
        <dd class="mono">{host.kernel}</dd>
        <dt>Processor</dt>
        <dd>
          {host.cpu_count}
          {host.cpu_count === 1 ? 'CPU' : 'CPUs'}{host.facts.cpu_model
            ? `, ${host.facts.cpu_model}`
            : ''}
        </dd>
        <dt>Memory</dt>
        <dd>{formatBytes(host.memory_bytes)}</dd>
        <dt>Addresses</dt>
        <dd class="mono">{host.facts.ips || '—'}</dd>
        <dt>Last boot</dt>
        <dd>{formatTime(booted)}</dd>
        <dt>First seen</dt>
        <dd>{formatTime(host.first_seen_at)}</dd>
        <dt>Last seen</dt>
        <dd>{formatTime(host.last_seen_at)}</dd>
        <dt>Agent</dt>
        <dd class="mono">{host.agent_id}</dd>
      </dl>

      <h2>Disks</h2>
      {#if disks.length === 0}
        <p class="muted">No disks reported.</p>
      {:else}
        <div class="table-wrap">
          <table class="data-table">
            <caption class="visually-hidden">Disks</caption>
            <thead>
              <tr
                ><th scope="col">Mount</th><th scope="col">Type</th><th scope="col" class="num"
                  >Size</th
                ></tr
              >
            </thead>
            <tbody>
              {#each disks as d (d.mount)}
                <tr>
                  <th scope="row" class="mono">{d.mount}</th>
                  <td>{d.fstype}</td>
                  <td class="num">{formatBytes(d.total)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}

      <h2>Containers <span class="muted">({containers.length})</span></h2>
      {#if containers.length === 0}
        <p class="muted">No containers on this host.</p>
      {:else}
        <div class="table-wrap">
          <table class="data-table">
            <caption class="visually-hidden">Containers on {host.hostname}</caption>
            <thead>
              <tr>
                <th scope="col">State</th>
                <th scope="col">Container</th>
                <th scope="col">Image</th>
                <th scope="col" class="num">Restarts</th>
              </tr>
            </thead>
            <tbody>
              {#each containers as c (c.id)}
                <tr>
                  <td><StatusBadge status={c.state} /></td>
                  <th scope="row"><a href="/inventory/containers/{c.id}">{c.name}</a></th>
                  <td class="mono wrap" title={c.image}>{c.image}</td>
                  <td class="num">{c.restart_count}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/snippet}
    {#snippet logs()}
      <JournalLogs hostId={host.id} />
    {/snippet}
  </ItemPage>
{:else if missing}
  <NotFoundItem what="host" />
{:else}
  <h1 id="page-title" tabindex="-1">Host</h1>
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

  .muted {
    color: var(--color-text-muted);
    font-weight: 400;
  }
</style>
