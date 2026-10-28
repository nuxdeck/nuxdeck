<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    ApiRequestError,
    type AlertItem,
    type AlertStateFilter,
    type ApiError,
  } from '../api/client';
  import EmptyState from '../ui/EmptyState.svelte';
  import FormError from '../ui/FormError.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import { alertRoute, canOperate, kindLabel, since } from './model';
  import SeverityBadge from './SeverityBadge.svelte';

  const REFRESH_MS = 30_000;
  const RANK: Record<string, number> = { critical: 0, warning: 1, info: 2 };

  const canAck = $derived(canOperate());

  let items = $state<AlertItem[]>([]);
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  let actionError = $state<ApiError | null>(null);
  let stateFilter = $state<AlertStateFilter>('active');
  let severity = $state('');
  let acking = $state<Record<string, boolean>>({});
  let announce = $state('');
  let gen = 0;

  const stateOptions = [
    { value: 'active', label: 'Active (open and acknowledged)' },
    { value: 'open', label: 'Open' },
    { value: 'acked', label: 'Acknowledged' },
    { value: 'resolved', label: 'Resolved' },
  ];
  const severityOptions = [
    { value: '', label: 'All severities' },
    { value: 'critical', label: 'Critical' },
    { value: 'warning', label: 'Warning' },
    { value: 'info', label: 'Info' },
  ];

  const sorted = $derived(
    [...items].sort(
      (a, b) =>
        (RANK[a.severity] ?? 3) - (RANK[b.severity] ?? 3) || b.opened_at.localeCompare(a.opened_at),
    ),
  );

  async function load(): Promise<void> {
    const mine = ++gen;
    try {
      const list = await api.alerts({ state: stateFilter, severity });
      if (mine !== gen) return;
      items = list;
      failure = null;
    } catch (e) {
      if (mine !== gen) return;
      if (e instanceof ApiRequestError) failure = e.error;
      else throw e;
    } finally {
      if (mine === gen) loaded = true;
    }
  }

  async function ack(a: AlertItem): Promise<void> {
    acking = { ...acking, [a.id]: true };
    actionError = null;
    try {
      const updated = await api.ackAlert(a.id);
      items = items.map((x) => (x.id === a.id ? updated : x));
      announce = `Acknowledged: ${a.summary}`;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
      // Already resolved by the time the click landed: show the real state.
      if (e.error.status === 409) await load();
    } finally {
      acking = { ...acking, [a.id]: false };
    }
  }

  onMount(() => {
    void load();
    const timer = setInterval(() => {
      if (!document.hidden) void load();
    }, REFRESH_MS);
    return () => clearInterval(timer);
  });

  function changed(): void {
    loaded = false;
    void load();
  }
</script>

<div class="toolbar">
  <SelectField
    id="alert-state"
    label="Show"
    bind:value={() => stateFilter, (v) => (stateFilter = v as AlertStateFilter)}
    options={stateOptions}
    onchange={changed}
  />
  <SelectField
    id="alert-severity"
    label="Severity"
    bind:value={severity}
    options={severityOptions}
    onchange={changed}
  />
  {#if loaded && !failure}<p class="count">{items.length} alerts</p>{/if}
</div>
<p class="visually-hidden" role="status">{announce}</p>

{#if failure}
  <FormError error={failure} />
{:else if !loaded}
  <p role="status">Loading…</p>
{:else}
  {#if actionError}<FormError error={actionError} />{/if}
  {#if sorted.length === 0}
    <EmptyState title={stateFilter === 'resolved' ? 'No resolved alerts' : 'No active alerts'}>
      {#if stateFilter === 'resolved'}Alerts that clear appear here for 90 days.{:else}Nothing is
        firing. Alerts open when a rule's condition holds.{/if}
    </EmptyState>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <caption class="visually-hidden">Alerts</caption>
        <thead>
          <tr>
            <th scope="col">Severity</th>
            <th scope="col">Item</th>
            <th scope="col">Rule</th>
            <th scope="col">Since</th>
            <th scope="col">State</th>
            <th scope="col" class="num">Flaps</th>
            <th scope="col"><span class="visually-hidden">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each sorted as a (a.id)}
            {@const route = alertRoute(a)}
            <tr>
              <td><SeverityBadge severity={a.severity} /></td>
              <th scope="row" class="name">
                {#if route}<a href={route}>{a.item_name}</a>{:else}{a.item_name}{/if}
                <span class="kind">{a.item_type}</span>
              </th>
              <td class="wrap" title={a.rule_name}
                >{a.rule_name} <span class="kind">{kindLabel(a.kind)}</span></td
              >
              <td title={a.opened_at}>{since(a.opened_at)}</td>
              <td>
                {#if a.state === 'acked'}
                  Acknowledged{a.acked_by ? ` by ${a.acked_by}` : ''}
                {:else if a.state === 'resolved'}
                  Resolved{a.resolve_reason ? `: ${a.resolve_reason}` : ''}
                {:else}
                  Open
                {/if}
              </td>
              <td class="num">{a.flap_count}</td>
              <td>
                <a href="/alerts/{a.id}" aria-label="Details of {a.summary}">Details</a>
                {#if canAck && a.state === 'open'}
                  <button
                    type="button"
                    class="link"
                    disabled={acking[a.id]}
                    aria-label="Acknowledge {a.summary}"
                    onclick={() => void ack(a)}
                    >{acking[a.id] ? 'Acknowledging…' : 'Acknowledge'}</button
                  >
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-4);
    margin-bottom: var(--space-3);
  }

  .count {
    margin: 0;
    padding-bottom: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .name {
    max-width: 28ch;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .kind {
    margin-left: var(--space-1);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
    font-weight: 400;
  }

  .link {
    min-height: var(--target-size);
    padding: 0 var(--space-2);
    border: 0;
    background: none;
    color: var(--color-accent);
    cursor: pointer;
    font: inherit;
    text-decoration: underline;
  }

  .link:disabled {
    cursor: progress;
    opacity: 0.7;
  }
</style>
