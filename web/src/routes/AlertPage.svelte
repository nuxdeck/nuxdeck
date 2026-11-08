<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiRequestError, type AlertItem, type ApiError } from '../lib/api/client';
  import { alertRoute, canOperate, itemTypeLabel, kindLabel, since } from '../lib/alerts/model';
  import { itemSilence, SILENCE_PRESETS } from '../lib/alerts/silences';
  import SeverityBadge from '../lib/alerts/SeverityBadge.svelte';
  import { formatTime } from '../lib/format';
  import { router } from '../lib/router.svelte';
  import Button from '../lib/ui/Button.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';

  let { id }: { id: string } = $props();

  const canWrite = $derived(canOperate());

  let alert = $state<AlertItem | null>(null);
  let loading = $state(true);
  let missing = $state(false);
  let failure = $state<ApiError | null>(null);
  let actionError = $state<ApiError | null>(null);
  let busy = $state(false);
  let announce = $state('');

  const route = $derived(alert ? alertRoute(alert) : null);

  $effect(() => {
    router.titleOverride = alert ? `Alert: ${alert.item_name}` : null;
  });

  async function load(): Promise<void> {
    try {
      alert = await api.alert(id);
      failure = null;
    } catch (e) {
      if (e instanceof ApiRequestError && e.error.status === 404) missing = true;
      else if (e instanceof ApiRequestError) failure = e.error;
      else throw e;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
    const timer = setInterval(() => {
      if (!document.hidden) void load();
    }, 30_000);
    return () => clearInterval(timer);
  });

  async function ack(): Promise<void> {
    busy = true;
    actionError = null;
    try {
      alert = await api.ackAlert(id);
      announce = 'Alert acknowledged';
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
      if (e.error.status === 409) await load();
    } finally {
      busy = false;
    }
  }

  async function silence(hours: number, label: string): Promise<void> {
    if (!alert) return;
    busy = true;
    actionError = null;
    try {
      await api.createSilence(itemSilence(alert.item_id, hours, alert.item_name));
      announce = `Notifications for ${alert.item_name} are silenced for ${label}`;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
    } finally {
      busy = false;
    }
  }
</script>

<nav class="crumbs" aria-label="Breadcrumb"><a href="/alerts">Alerts</a> / Alert</nav>
<h1 id="page-title" tabindex="-1">Alert</h1>
<p class="visually-hidden" role="status">{announce}</p>

{#if missing}
  <EmptyState title="Alert not found">
    This alert does not exist or was removed after 90 days. Go back to the <a href="/alerts"
      >alerts</a
    >.
  </EmptyState>
{:else if failure}
  <FormError error={failure} />
{:else if loading || !alert}
  <p role="status">Loading…</p>
{:else}
  <section class="summary" aria-labelledby="alert-summary">
    <SeverityBadge severity={alert.severity} />
    <h2 id="alert-summary">{alert.summary}</h2>
    {#if route}
      <a class="button-link" href={route}
        >Open {itemTypeLabel(alert.item_type).toLowerCase()}: {alert.item_name}</a
      >
    {:else}
      <p class="muted">{itemTypeLabel(alert.item_type)}: {alert.item_name}</p>
    {/if}
  </section>

  {#if actionError}<FormError error={actionError} />{/if}

  <dl class="facts">
    <div>
      <dt>State</dt>
      <dd>
        {alert.state === 'open' ? 'Open' : alert.state === 'acked' ? 'Acknowledged' : 'Resolved'}
      </dd>
    </div>
    <div>
      <dt>Rule</dt>
      <dd>{alert.rule_name} ({kindLabel(alert.kind)})</dd>
    </div>
    <div>
      <dt>Opened</dt>
      <dd>{formatTime(alert.opened_at)} ({since(alert.opened_at)})</dd>
    </div>
    {#if alert.acked_at}
      <div>
        <dt>Acknowledged</dt>
        <dd>{formatTime(alert.acked_at)}{alert.acked_by ? ` by ${alert.acked_by}` : ''}</dd>
      </div>
    {/if}
    {#if alert.resolved_at}
      <div>
        <dt>Resolved</dt>
        <dd>
          {formatTime(alert.resolved_at)}{alert.resolve_reason ? `: ${alert.resolve_reason}` : ''}
        </dd>
      </div>
    {/if}
    <div>
      <dt>Last notified</dt>
      <dd>{formatTime(alert.last_notified_at)}</dd>
    </div>
    <div>
      <dt>Flaps in the last 30 minutes</dt>
      <dd>{alert.flap_count}</dd>
    </div>
  </dl>

  {#if canWrite && alert.state !== 'resolved'}
    <div class="actions">
      {#if alert.state === 'open'}
        <Button variant="secondary" disabled={busy} onclick={() => void ack()}>Acknowledge</Button>
      {/if}
      <div role="group" aria-label="Silence this item">
        <span class="label">Silence this item for</span>
        {#each SILENCE_PRESETS as p (p.hours)}
          <Button variant="secondary" disabled={busy} onclick={() => void silence(p.hours, p.label)}
            >{p.label}</Button
          >
        {/each}
      </div>
    </div>
    <p class="muted">
      A silence stops notifications for this item only. The alert still opens and is recorded.
    </p>
  {/if}
{/if}

<style>
  .crumbs {
    margin-bottom: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  h1 {
    margin-bottom: var(--space-4);
    font-size: var(--font-size-xl);
  }

  h1:focus {
    outline: none;
  }

  .summary {
    display: grid;
    gap: var(--space-3);
    justify-items: start;
    margin-bottom: var(--space-4);
  }

  h2 {
    font-size: var(--font-size-lg);
    overflow-wrap: anywhere;
  }

  .facts {
    display: grid;
    gap: var(--space-2);
    margin: var(--space-4) 0;
  }

  .facts div {
    display: grid;
    grid-template-columns: minmax(10rem, 16rem) 1fr;
    gap: var(--space-3);
  }

  dt {
    color: var(--color-text-muted);
    font-weight: 600;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-4);
  }

  [role='group'] {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }

  .label {
    font-weight: 600;
  }

  .muted {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }
</style>
