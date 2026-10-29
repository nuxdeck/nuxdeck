<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    api,
    ApiRequestError,
    auditExportUrl,
    type ApiError,
    type AuditEntry,
    type AuditQuery,
    type AuditVerification,
  } from '../lib/api/client';
  import { isAdmin } from '../lib/alerts/model';
  import { formatTime } from '../lib/format';
  import { findSection } from '../lib/router.svelte';
  import Button from '../lib/ui/Button.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import Icon from '../lib/ui/Icon.svelte';
  import SelectField from '../lib/ui/SelectField.svelte';
  import TextField from '../lib/ui/TextField.svelte';

  const PAGE = 50;
  const section = findSection('/audit');
  const admin = $derived(isAdmin());

  let actor = $state('');
  let action = $state('');
  let targetType = $state('');
  let targetId = $state('');
  const filtered = $derived(Boolean(actor || action || targetType || targetId));
  let result = $state('');
  let from = $state('');
  let to = $state('');
  let text = $state('');

  let applied = $state<AuditQuery>({});
  let items = $state<AuditEntry[]>([]);
  let next = $state<string | null>(null);
  let loaded = $state(false);
  let loadingMore = $state(false);
  let failure = $state<ApiError | null>(null);
  let verification = $state<AuditVerification | null>(null);
  let verifyFailure = $state<ApiError | null>(null);
  let selected = $state<AuditEntry | null>(null);
  let closeButton = $state<HTMLButtonElement | null>(null);
  let opener: HTMLElement | null = null;
  let gen = 0;

  const resultOptions = [
    { value: '', label: 'Any result' },
    { value: 'success', label: 'Success' },
    { value: 'failure', label: 'Failure' },
  ];

  /** A datetime-local value is local time without a zone; the server wants an instant. */
  const instant = (v: string): string => {
    const d = new Date(v);
    return v && !Number.isNaN(d.getTime()) ? d.toISOString() : '';
  };

  const exportHref = $derived(auditExportUrl(applied));

  async function load(more: boolean): Promise<void> {
    const mine = ++gen;
    if (more) loadingMore = true;
    try {
      const page = await api.auditSearch({
        ...applied,
        limit: PAGE,
        cursor: more && next ? next : undefined,
      });
      if (mine !== gen) return;
      items = more ? [...items, ...page.items] : page.items;
      next = page.next_cursor;
      failure = null;
    } catch (e) {
      if (mine !== gen) return;
      if (e instanceof ApiRequestError) failure = e.error;
      else throw e;
    } finally {
      if (mine === gen) {
        loaded = true;
        loadingMore = false;
      }
    }
  }

  async function verify(): Promise<void> {
    verifyFailure = null;
    try {
      verification = await api.auditVerify();
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      verifyFailure = e.error;
    }
  }

  function apply(e: SubmitEvent): void {
    e.preventDefault();
    applied = {
      actor: actor.trim(),
      action: action.trim(),
      target_type: targetType.trim(),
      target_id: targetId.trim(),
      result,
      from: instant(from),
      to: instant(to),
      q: text.trim(),
    };
    loaded = false;
    void load(false);
  }

  function reset(): void {
    actor = action = targetType = targetId = result = from = to = text = '';
    applied = {};
    loaded = false;
    void load(false);
  }

  async function open(entry: AuditEntry, el: HTMLElement): Promise<void> {
    opener = el;
    selected = entry;
    await tick();
    closeButton?.focus();
  }

  function close(): void {
    selected = null;
    opener?.focus();
  }

  function onKey(e: KeyboardEvent): void {
    if (e.key === 'Escape' && selected) close();
  }

  onMount(() => {
    if (!admin) {
      loaded = true;
      return;
    }
    void load(false);
    void verify();
  });
</script>

<svelte:window onkeydown={onKey} />

<h1 id="page-title" tabindex="-1">{section?.title}</h1>
<p class="question">{section?.question}</p>

{#if !admin}
  <EmptyState title="Administrators only">
    The audit log is visible to administrators. Ask one for the entries you need.
  </EmptyState>
{:else}
  <div class="verify" role="status">
    {#if verifyFailure}
      <FormError error={verifyFailure} />
    {:else if !verification}
      <span>Checking the chain…</span>
    {:else if verification.ok}
      <span class="badge ok"><Icon name="checkCircle" size={16} /> Chain verified</span>
      <span class="muted">{verification.entries} entries, none altered.</span>
    {:else}
      <span class="badge bad"><Icon name="xCircle" size={16} /> Chain broken</span>
      <span>
        Entry {verification.broken_at} does not verify: {verification.reason}
        <span class="mono">({verification.code})</span>
      </span>
    {/if}
    <button type="button" class="link" onclick={verify}>Verify again</button>
  </div>

  <form class="filters" onsubmit={apply} aria-label="Filter audit entries">
    <TextField id="audit-actor" label="Actor ID" bind:value={actor} mono maxlength={256} />
    <TextField
      id="audit-action"
      label="Action starts with"
      bind:value={action}
      placeholder="check."
      mono
      maxlength={256}
    />
    <TextField id="audit-ttype" label="Target type" bind:value={targetType} maxlength={256} />
    <TextField id="audit-tid" label="Target ID" bind:value={targetId} mono maxlength={256} />
    <SelectField id="audit-result" label="Result" bind:value={result} options={resultOptions} />
    <div class="field">
      <label for="audit-from">From</label>
      <input id="audit-from" type="datetime-local" bind:value={from} />
    </div>
    <div class="field">
      <label for="audit-to">To</label>
      <input id="audit-to" type="datetime-local" bind:value={to} />
    </div>
    <TextField id="audit-q" label="Search details" bind:value={text} maxlength={256} />
    <div class="actions">
      <Button type="submit">Search</Button>
      <Button variant="secondary" onclick={reset}>Clear</Button>
      <a class="button-link" href={exportHref} download>Export JSON lines</a>
    </div>
  </form>

  {#if failure}
    <FormError error={failure} />
  {:else if !loaded}
    <p role="status">Loading…</p>
  {:else if items.length === 0}
    <EmptyState title={filtered ? 'No audit entries match' : 'No audit entries yet'}>
      {#if filtered}
        Change the filters, or clear them to see every entry.
      {:else}
        Changes to hosts, checks, alerts, settings and users are recorded here as they happen.
      {/if}
    </EmptyState>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <caption class="visually-hidden">Audit entries, newest first</caption>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Actor</th>
            <th scope="col">Action</th>
            <th scope="col">Target</th>
            <th scope="col">Result</th>
            <th scope="col">IP</th>
            <th scope="col"><span class="visually-hidden">Detail</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as e (e.id)}
            <tr>
              <td>{formatTime(e.ts)}</td>
              <td class="wrap mono" title={e.actor_id}
                >{e.actor_type}{e.actor_id ? `:${e.actor_id}` : ''}</td
              >
              <td class="mono">{e.action}</td>
              <td class="wrap mono" title={e.target_id}
                >{e.target_type}{e.target_id ? `:${e.target_id}` : ''}</td
              >
              <td>
                <span class="badge {e.result === 'success' ? 'ok' : 'bad'}">
                  <Icon name={e.result === 'success' ? 'checkCircle' : 'xCircle'} size={16} />
                  {e.result === 'success' ? 'Success' : 'Failure'}
                </span>
              </td>
              <td class="mono">{e.ip}</td>
              <td>
                <button
                  type="button"
                  class="link"
                  onclick={(ev) => open(e, ev.currentTarget)}
                  aria-label="Details of entry {e.id}, {e.action}">Details</button
                >
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if next}
      <div class="more">
        <Button variant="secondary" disabled={loadingMore} onclick={() => load(true)}>
          {loadingMore ? 'Loading…' : 'Load older entries'}
        </Button>
      </div>
    {/if}
  {/if}
{/if}

{#if selected}
  <!-- Non-modal side panel: focus is not trapped, so it is a labelled region rather than a dialog. Escape closes it. -->
  <aside class="drawer" aria-labelledby="audit-drawer-title">
    <div class="drawer-head">
      <h2 id="audit-drawer-title">Entry {selected.id}</h2>
      <button type="button" class="link" bind:this={closeButton} onclick={close}>Close</button>
    </div>
    <dl>
      <dt>Time</dt>
      <dd>{selected.ts}</dd>
      <dt>Actor</dt>
      <dd class="mono">{selected.actor_type}:{selected.actor_id}</dd>
      <dt>Action</dt>
      <dd class="mono">{selected.action}</dd>
      <dt>Target</dt>
      <dd class="mono">{selected.target_type}:{selected.target_id}</dd>
      <dt>Result</dt>
      <dd>{selected.result}</dd>
      <dt>Source IP</dt>
      <dd class="mono">{selected.ip}</dd>
      <dt>Details</dt>
      <dd><pre>{JSON.stringify(selected.details, null, 2)}</pre></dd>
      <dt>Previous hash</dt>
      <dd class="mono hash">{selected.prev_hash || '—'}</dd>
      <dt>Hash</dt>
      <dd class="mono hash">{selected.hash}</dd>
    </dl>
  </aside>
{/if}

<style>
  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  .question {
    margin: var(--space-1) 0 var(--space-4);
    color: var(--color-text-muted);
  }

  .muted {
    color: var(--color-text-muted);
  }

  .verify {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }

  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    font-weight: 600;
  }

  .badge.ok {
    color: var(--color-status-healthy);
  }

  .badge.bad {
    color: var(--color-status-critical);
  }

  .filters {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(14rem, 1fr));
    gap: var(--space-3);
    margin-bottom: var(--space-4);
  }

  .field {
    display: grid;
    gap: var(--space-1);
  }

  .field input {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: var(--space-2);
  }

  .more {
    margin-top: var(--space-3);
  }

  .link {
    min-height: var(--target-size);
    padding: 0 var(--space-2);
    border: 0;
    background: none;
    color: var(--color-accent);
    font: inherit;
    text-decoration: underline;
    cursor: pointer;
  }

  .drawer {
    position: fixed;
    inset: 0 0 0 auto;
    z-index: 20;
    width: min(32rem, 100%);
    padding: var(--space-4);
    overflow-y: auto;
    border-left: 1px solid var(--color-border-strong);
    background: var(--color-surface);
    box-shadow: var(--shadow-dialog);
  }

  .drawer-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--space-3);
  }

  .drawer-head h2 {
    font-size: var(--font-size-lg);
  }

  dt {
    margin-top: var(--space-3);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  .hash {
    font-size: var(--font-size-sm);
  }

  pre {
    margin: 0;
    padding: var(--space-2);
    overflow-x: auto;
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }
</style>
