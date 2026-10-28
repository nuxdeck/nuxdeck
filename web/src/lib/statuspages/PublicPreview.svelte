<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { api, ApiRequestError, type PublicLevel, type PublicStatus } from '../api/client';
  import { formatTime } from '../format';
  import Button from '../ui/Button.svelte';
  import { publicUrl } from './form';

  interface Props {
    slug: string;
    published: boolean;
    /** Changes whenever the saved page or its incidents change, so the preview reloads. */
    version?: string;
  }

  let { slug, published, version = '' }: Props = $props();

  const LABEL: Record<PublicLevel, string> = {
    operational: 'Operational',
    degraded: 'Degraded',
    outage: 'Outage',
    unknown: 'Unknown',
  };
  const TONE: Record<PublicLevel, string> = {
    operational: 'healthy',
    degraded: 'warning',
    outage: 'critical',
    unknown: 'unknown',
  };

  let data = $state<PublicStatus | null>(null);
  let loading = $state(false);
  let failed = $state(false);

  async function load(): Promise<void> {
    if (!published) {
      data = null;
      return;
    }
    loading = true;
    failed = false;
    try {
      data = await api.publicStatus(slug);
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failed = true;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void [slug, published, version];
    void load();
  });
</script>

<section class="preview" aria-labelledby="preview-title">
  <div class="head">
    <h2 id="preview-title">Public preview</h2>
    {#if published}
      <Button variant="secondary" onclick={() => void load()} disabled={loading}>Refresh</Button>
    {/if}
  </div>
  <p class="hint">
    This is what visitors see at <span class="mono">{publicUrl(slug)}</span>, read from the public
    endpoint.
  </p>
  {#if !published}
    <p class="note" role="status">Publish the page to see its public preview.</p>
  {:else if loading && !data}
    <p role="status">Loading…</p>
  {:else if failed}
    <p class="note" role="status">The public page could not be read. Try Refresh.</p>
  {:else if data === null}
    <p class="note" role="status">
      The public page is not available yet. It appears a moment after you save.
    </p>
  {:else}
    <div class="page">
      <h3>{data.title}</h3>
      {#if data.description}<p class="desc">{data.description}</p>{/if}
      <p class="overall {TONE[data.status]}">
        Overall: <strong>{LABEL[data.status]}</strong>
      </p>
      {#each data.incidents as inc (inc.started_at + inc.title)}
        <div class="incident">
          <p class="inc-title">{inc.title}</p>
          <p class="meta">
            {inc.status}, {inc.impact} impact, started {formatTime(inc.started_at)}
          </p>
          <p class="body">{inc.body}</p>
        </div>
      {/each}
      <ul class="components">
        {#each data.components as c (c.name)}
          <li>
            <div class="row">
              <span class="name">{c.name}</span>
              <span class="badge {TONE[c.status]}">{LABEL[c.status]}</span>
            </div>
            <div class="bars" aria-hidden="true">
              {#each c.days as d (d.date)}
                <span class="day {TONE[d.status]}" title="{d.date}: {LABEL[d.status]}"></span>
              {/each}
            </div>
            <p class="meta">
              {c.uptime_90d === null
                ? 'No uptime data for the last 90 days'
                : `${c.uptime_90d}% uptime over the last 90 days`}
            </p>
          </li>
        {/each}
      </ul>
    </div>
  {/if}
</section>

<style>
  .preview {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
  }

  h2 {
    font-size: var(--font-size-lg);
  }

  h3 {
    font-size: var(--font-size-md);
  }

  .hint,
  .meta,
  .desc {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .page {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-4);
    border: 1px dashed var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-bg);
  }

  .overall {
    justify-self: start;
    margin: 0;
    padding: var(--space-1) var(--space-3);
    border-radius: var(--radius-1);
  }

  .incident {
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
    background: var(--color-surface);
  }

  .inc-title {
    margin: 0;
    font-weight: 700;
  }

  .body {
    margin: var(--space-1) 0 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .components {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2);
  }

  .name {
    font-weight: 600;
  }

  .badge {
    padding: 0 var(--space-2);
    border-radius: var(--radius-1);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .bars {
    display: grid;
    grid-template-columns: repeat(90, 1fr);
    gap: 1px;
    margin: var(--space-2) 0 var(--space-1);
  }

  .day {
    display: block;
    height: var(--space-4);
  }

  .overall.healthy,
  .badge.healthy {
    color: var(--color-status-healthy);
    background: var(--color-status-healthy-bg);
  }

  .overall.warning,
  .badge.warning {
    color: var(--color-status-warning);
    background: var(--color-status-warning-bg);
  }

  .overall.critical,
  .badge.critical {
    color: var(--color-status-critical);
    background: var(--color-status-critical-bg);
  }

  .overall.unknown,
  .badge.unknown {
    color: var(--color-status-unknown);
    background: var(--color-status-unknown-bg);
  }

  .day.healthy {
    background: var(--color-status-healthy);
  }

  .day.warning {
    background: var(--color-status-warning);
  }

  .day.critical {
    background: var(--color-status-critical);
  }

  .day.unknown {
    background: var(--color-border);
  }
</style>
