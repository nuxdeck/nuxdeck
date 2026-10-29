<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Rule, type RuleInput } from '../api/client';
  import EmptyState from '../ui/EmptyState.svelte';
  import FormError from '../ui/FormError.svelte';
  import { canOperate, kindLabel, selectorSummary } from './model';
  import RuleEditor from './RuleEditor.svelte';
  import SeverityBadge from './SeverityBadge.svelte';

  const canWrite = $derived(canOperate());

  let items = $state<Rule[]>([]);
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  let actionError = $state<ApiError | null>(null);
  // undefined: the list; null: a new rule; a string: that rule.
  let editing = $state<string | null | undefined>(undefined);
  let confirming = $state<string | null>(null);
  let busy = $state<Record<string, boolean>>({});
  let announce = $state('');

  async function load(): Promise<void> {
    try {
      items = await api.rules();
      failure = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
    } finally {
      loaded = true;
    }
  }

  onMount(() => void load());

  const inputOf = (r: Rule, enabled: boolean): RuleInput => ({
    name: r.name,
    kind: r.kind,
    severity: r.severity,
    enabled,
    selector: { tags: r.selector.tags, ids: r.selector.ids },
    params: r.params,
  });

  // The change is a full replace, so read the current version first and send its ETag.
  async function toggle(r: Rule, enabled: boolean): Promise<void> {
    busy = { ...busy, [r.id]: true };
    actionError = null;
    try {
      const current = await api.rule(r.id);
      const saved = await api.updateRule(r.id, inputOf(current.rule, enabled), current.etag);
      items = items.map((x) => (x.id === r.id ? saved.rule : x));
      announce = `${r.name} ${enabled ? 'enabled' : 'disabled'}`;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
      await load();
    } finally {
      busy = { ...busy, [r.id]: false };
    }
  }

  async function remove(r: Rule): Promise<void> {
    busy = { ...busy, [r.id]: true };
    actionError = null;
    try {
      await api.deleteRule(r.id);
      items = items.filter((x) => x.id !== r.id);
      announce = `Deleted rule ${r.name}`;
      confirming = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
    } finally {
      busy = { ...busy, [r.id]: false };
    }
  }

  async function closeEditor(saved: boolean): Promise<void> {
    editing = undefined;
    if (saved) announce = 'Rule saved';
    await load();
    await tick();
    document.getElementById('page-title')?.focus();
  }
</script>

<p class="visually-hidden" role="status">{announce}</p>

{#if editing !== undefined}
  {#key editing}
    <RuleEditor id={editing ?? undefined} onclose={(saved) => void closeEditor(saved)} />
  {/key}
{:else}
  <div class="bar">
    <p class="intro">
      Rules decide when an alert opens. Notifications follow the routes in Channels and Routes.
    </p>
    {#if canWrite}
      <button type="button" class="button-link" onclick={() => (editing = null)}>Add rule</button>
    {/if}
  </div>

  {#if failure}
    <FormError error={failure} />
  {:else if !loaded}
    <p role="status">Loading…</p>
  {:else}
    {#if actionError}<FormError error={actionError} />{/if}
    {#if items.length === 0}
      <EmptyState title="No rules yet">
        Without a rule nothing alerts.
        {#if canWrite}Add one to be told when a check goes down or a host goes offline.{:else}An
          operator can add one.{/if}
      </EmptyState>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <caption class="visually-hidden">Alert rules</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Condition</th>
              <th scope="col">Severity</th>
              <th scope="col">Applies to</th>
              <th scope="col">Enabled</th>
              {#if canWrite}<th scope="col"><span class="visually-hidden">Actions</span></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each items as r (r.id)}
              <tr>
                <th scope="row" class="name">{r.name}</th>
                <td>{kindLabel(r.kind)}</td>
                <td><SeverityBadge severity={r.severity} /></td>
                <td class="wrap">{selectorSummary(r.selector)}</td>
                <td>
                  {#if canWrite}
                    <input
                      type="checkbox"
                      checked={r.enabled}
                      disabled={busy[r.id]}
                      aria-label="Enabled: {r.name}"
                      onchange={(e) => void toggle(r, e.currentTarget.checked)}
                    />
                  {:else}
                    {r.enabled ? 'Yes' : 'No'}
                  {/if}
                </td>
                {#if canWrite}
                  <td>
                    {#if confirming === r.id}
                      <span>Delete {r.name}?</span>
                      <button
                        type="button"
                        class="link danger"
                        disabled={busy[r.id]}
                        onclick={() => void remove(r)}>Yes, delete</button
                      >
                      <button type="button" class="link" onclick={() => (confirming = null)}
                        >Cancel</button
                      >
                    {:else}
                      <button
                        type="button"
                        class="link"
                        aria-label="Edit {r.name}"
                        onclick={() => (editing = r.id)}>Edit</button
                      >
                      <button
                        type="button"
                        class="link"
                        aria-label="Delete {r.name}"
                        onclick={() => (confirming = r.id)}>Delete</button
                      >
                    {/if}
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
{/if}

<style>
  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  .intro {
    margin: 0;
    color: var(--color-text-muted);
  }

  .button-link {
    cursor: pointer;
    font: inherit;
    font-weight: 600;
  }

  /* 24 px is the WCAG 2.2 minimum target (2.5.8); the default checkbox is 13 px. */
  input[type='checkbox'] {
    width: 1.5rem;
    height: 1.5rem;
  }

  .name {
    max-width: 28ch;
    overflow: hidden;
    text-overflow: ellipsis;
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

  .danger {
    color: var(--color-status-critical);
    font-weight: 600;
  }
</style>
