<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { findSection } from '../lib/router.svelte';
  import { formatTime } from '../lib/format';
  import type { Container, Host } from '../lib/api/client';
  import { inventory, type LiveStatus } from '../lib/inventory.svelte';
  import { ENV_KEY, groupByEnv, hasTag, tagOptions, tagText, type Tags } from '../lib/tags';
  import Button from '../lib/ui/Button.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import Icon from '../lib/ui/Icon.svelte';
  import TagChips from '../lib/ui/TagChips.svelte';
  import StatusBadge from '../lib/ui/StatusBadge.svelte';

  const section = findSection('/inventory');
  let filter = $state('');

  let tagFilter = $state('');
  let groupByEnvironment = $state(false);

  const hostName = $derived(new Map(inventory.hosts.map((h) => [h.id, h.hostname])));
  const hostById = $derived(new Map(inventory.hosts.map((h) => [h.id, h])));
  const needle = $derived(filter.trim().toLowerCase());

  // A container belongs to its host's environment unless it has an environment of its own.
  const containerTags = (c: Container): Tags => ({ ...hostById.get(c.host_id)?.tags, ...c.tags });
  const options = $derived(
    tagOptions([...inventory.hosts.map((h) => h.tags), ...inventory.containers.map(containerTags)]),
  );
  const envOf = (tags: Tags): string => tags[ENV_KEY] ?? '';

  const hosts = $derived(
    inventory.hosts.filter(
      (h) =>
        (!tagFilter || hasTag(h.tags, tagFilter)) &&
        (!needle ||
          [h.hostname, h.distro, h.facts.ips ?? '', h.owner, ...tagText(h.tags)].some((t) =>
            t.toLowerCase().includes(needle),
          )),
    ),
  );
  const containers = $derived(
    inventory.containers.filter(
      (c) =>
        (!tagFilter || hasTag(containerTags(c), tagFilter)) &&
        (!needle ||
          [c.name, c.image, hostName.get(c.host_id) ?? '', c.owner, ...tagText(c.tags)].some((t) =>
            t.toLowerCase().includes(needle),
          )),
    ),
  );
  const hostGroups = $derived(
    groupByEnvironment
      ? groupByEnv<Host>(hosts, (h) => envOf(h.tags))
      : [{ env: null, items: hosts }],
  );
  const containerGroups = $derived(
    groupByEnvironment
      ? groupByEnv<Container>(containers, (c) => envOf(containerTags(c)))
      : [{ env: null, items: containers }],
  );

  const liveText: Record<LiveStatus, string> = {
    idle: 'Not connected',
    loading: 'Loading…',
    live: 'Live',
    reconnecting: 'Reconnecting…',
    failed: 'Live updates unavailable',
  };

  function counts(hostId: string): string {
    const all = inventory.containersOf(hostId);
    return `${all.filter((c) => c.state === 'running').length} / ${all.length}`;
  }

  function retry(): void {
    inventory.stop();
    inventory.start();
  }
</script>

<div class="head">
  <div>
    <h1 id="page-title" tabindex="-1">{section?.title}</h1>
    <p class="question">{section?.question}</p>
  </div>
  <a class="button-link" href="/inventory/add"><Icon name="plus" size={16} /> Add host</a>
</div>

<p class="live" class:bad={inventory.status === 'failed'}>
  <Icon
    name={inventory.status === 'live'
      ? 'checkCircle'
      : inventory.status === 'failed'
        ? 'alertTriangle'
        : 'refresh'}
    size={16}
  />
  {liveText[inventory.status]}
</p>
<p class="visually-hidden" role="status">{inventory.announcement}</p>

{#if !inventory.loaded && inventory.status === 'failed'}
  {#if inventory.failure}
    <FormError error={inventory.failure} />
  {:else}
    <EmptyState title="Could not load the inventory"
      >Check your connection, then try again.</EmptyState
    >
  {/if}
  <p class="retry"><Button variant="secondary" onclick={retry}>Try again</Button></p>
{:else if !inventory.loaded}
  <p role="status">Loading the inventory…</p>
{:else if inventory.hosts.length === 0}
  <EmptyState title="No hosts yet">
    Add your first host to see it and its containers here.
  </EmptyState>
  <p class="retry"><a class="button-link" href="/inventory/add">Add your first host</a></p>
{:else}
  <div class="tools">
    <label for="inventory-filter">Filter</label>
    <input
      id="inventory-filter"
      type="search"
      placeholder="Name, image, IP or tag"
      autocomplete="off"
      spellcheck="false"
      bind:value={filter}
    />
    <label for="inventory-tag">Tag</label>
    <select id="inventory-tag" bind:value={tagFilter}>
      <option value="">Any tag</option>
      {#each options as o (o)}<option value={o}>{o}</option>{/each}
    </select>
    <label class="check">
      <input type="checkbox" bind:checked={groupByEnvironment} />
      Group by environment
    </label>
    {#if inventory.pendingReorder > 0}
      <p class="reorder" role="status">
        {inventory.pendingReorder}
        {inventory.pendingReorder === 1 ? 'item' : 'items'} changed.
        <button type="button" onclick={() => inventory.refreshOrder()}>Refresh order</button>
      </p>
    {/if}
  </div>

  <h2>Hosts <span class="count">({hosts.length})</span></h2>
  <div class="table-wrap">
    <table class="data-table">
      <caption class="visually-hidden">Hosts, problems first</caption>
      <thead>
        <tr>
          <th scope="col">Status</th>
          <th scope="col">Host</th>
          <th scope="col">System</th>
          <th scope="col">Addresses</th>
          <th scope="col">Tags</th>
          <th scope="col" class="num">Containers running</th>
          <th scope="col">Last seen</th>
        </tr>
      </thead>
      {#each hostGroups as group (group.env ?? '*')}
        <tbody>
          {#if group.env !== null}
            <tr class="group"
              ><th scope="colgroup" colspan="7"
                >{group.env || 'No environment'}
                <span class="count">({group.items.length})</span></th
              ></tr
            >
          {/if}
          {#each group.items as h (h.id)}
            <tr>
              <td><StatusBadge status={h.status} /></td>
              <th scope="row"><a href="/inventory/hosts/{h.id}">{h.hostname}</a></th>
              <td>{h.distro || h.os}</td>
              <td class="mono">{h.facts.ips ?? '—'}</td>
              <td><TagChips tags={h.tags} /></td>
              <td class="num">{counts(h.id)}</td>
              <td>{formatTime(h.last_seen_at)}</td>
            </tr>
          {:else}
            <tr><td colspan="7">No host matches the filter.</td></tr>
          {/each}
        </tbody>
      {/each}
    </table>
  </div>

  <h2>Containers <span class="count">({containers.length})</span></h2>
  <div class="table-wrap">
    <table class="data-table">
      <caption class="visually-hidden">Containers, problems first</caption>
      <thead>
        <tr>
          <th scope="col">State</th>
          <th scope="col">Container</th>
          <th scope="col">Host</th>
          <th scope="col">Image</th>
          <th scope="col">Tags</th>
          <th scope="col" class="num">Published ports</th>
          <th scope="col" class="num">Restarts</th>
        </tr>
      </thead>
      {#each containerGroups as group (group.env ?? '*')}
        <tbody>
          {#if group.env !== null}
            <tr class="group"
              ><th scope="colgroup" colspan="7"
                >{group.env || 'No environment'}
                <span class="count">({group.items.length})</span></th
              ></tr
            >
          {/if}
          {#each group.items as c (c.id)}
            <tr>
              <td><StatusBadge status={c.state} /></td>
              <th scope="row"><a href="/inventory/containers/{c.id}">{c.name}</a></th>
              <td
                ><a href="/inventory/hosts/{c.host_id}"
                  >{hostName.get(c.host_id) ?? 'Unknown host'}</a
                ></td
              >
              <td class="mono wrap" title={c.image}>{c.image}</td>
              <td><TagChips tags={c.tags} /></td>
              <td class="num">{c.ports.length}</td>
              <td class="num">{c.restart_count}</td>
            </tr>
          {:else}
            <tr
              ><td colspan="7"
                >{#if inventory.containers.length === 0}No containers reported yet. Containers
                  appear once an agent reports a Docker or Podman host. <a href="/inventory/add"
                    >Add a host</a
                  >.{:else}No container matches the filter.{/if}</td
              ></tr
            >
          {/each}
        </tbody>
      {/each}
    </table>
  </div>
{/if}

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
  }

  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  h2 {
    margin: var(--space-6) 0 var(--space-2);
    font-size: var(--font-size-md);
  }

  .count {
    color: var(--color-text-muted);
    font-weight: 400;
  }

  .question {
    margin: var(--space-1) 0 var(--space-4);
    color: var(--color-text-muted);
  }

  .live {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    margin-bottom: var(--space-4);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .live.bad {
    color: var(--color-status-critical);
    font-weight: 600;
  }

  .tools {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }

  label {
    font-weight: 600;
  }

  input:not([type='checkbox']),
  select {
    min-height: var(--target-size);
    min-width: 16rem;
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  select {
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    min-height: var(--target-size);
    font-weight: 400;
  }

  .group th {
    background: var(--color-surface-sunken);
    text-align: left;
  }

  .reorder {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-1);
    background: var(--color-status-warning-bg);
    color: var(--color-status-warning);
    font-weight: 600;
  }

  .reorder button {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 1px solid currentcolor;
    border-radius: var(--radius-1);
    background: none;
    cursor: pointer;
    font-weight: 600;
  }

  .retry {
    margin-top: var(--space-3);
  }
</style>
