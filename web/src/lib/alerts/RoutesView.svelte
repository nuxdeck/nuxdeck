<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Channel } from '../api/client';
  import Button from '../ui/Button.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import FormError from '../ui/FormError.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import ToggleField from '../ui/ToggleField.svelte';
  import CheckGroup from './CheckGroup.svelte';
  import ChipInput from './ChipInput.svelte';
  import { isAdmin, RULE_KINDS, SEVERITIES } from './model';
  import {
    draftFrom,
    MAX_ROUTES,
    move,
    routesPayload,
    validateRoutes,
    type RouteDraft,
    type RouteErrors,
  } from './routes';

  const admin = $derived(isAdmin());

  let drafts = $state<RouteDraft[]>([]);
  let channels = $state<Channel[]>([]);
  let etag = $state('');
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  let saveError = $state<ApiError | null>(null);
  let errors = $state<RouteErrors>({});
  let saving = $state(false);
  let notice = $state('');
  let announce = $state('');

  const severityOptions = SEVERITIES.map((s) => ({
    value: s,
    label: s.charAt(0).toUpperCase() + s.slice(1),
  }));
  const kindOptions = RULE_KINDS.map((k) => ({ value: k.id, label: k.label }));
  const channelOptions = $derived([
    { value: '', label: 'Choose a channel' },
    ...channels.map((c) => ({ value: c.id, label: c.enabled ? c.name : `${c.name} (disabled)` })),
  ]);

  async function load(): Promise<void> {
    try {
      const [list, chans] = await Promise.all([api.routes(), api.channels()]);
      channels = chans;
      etag = list.etag;
      drafts = list.routes.map((r) => draftFrom(r));
      failure = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
    } finally {
      loaded = true;
    }
  }

  onMount(() => {
    if (admin) void load();
  });

  async function shift(i: number, delta: number): Promise<void> {
    const item = drafts[i];
    if (!item) return;
    drafts = move(drafts, i, delta);
    announce = `Route moved to position ${i + delta + 1} of ${drafts.length}`;
    await tick();
    // The moved row may now sit at an end, where one button is disabled; keep focus on a usable one.
    const want = delta < 0 ? 'up' : 'down';
    const other = delta < 0 ? 'down' : 'up';
    const el = document.getElementById(`route-${item.key}-${want}`) as HTMLButtonElement | null;
    if (el && !el.disabled) el.focus();
    else
      (document.getElementById(`route-${item.key}-${other}`) as HTMLButtonElement | null)?.focus();
  }

  function add(): void {
    drafts.push(draftFrom(undefined, channels[0]?.id ?? ''));
    announce = `Route ${drafts.length} added`;
    void tick().then(() => document.getElementById(`route-${drafts.at(-1)?.key}-tags`)?.focus());
  }

  function remove(i: number): void {
    drafts.splice(i, 1);
    errors = {};
    announce = 'Route removed';
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    saveError = null;
    notice = '';
    const found = validateRoutes(drafts, channels);
    errors = found;
    if (Object.keys(found).length > 0) {
      announce = 'Fix the highlighted routes before saving';
      return;
    }
    saving = true;
    try {
      const saved = await api.replaceRoutes(routesPayload(drafts), etag);
      etag = saved.etag;
      drafts = saved.routes.map((r) => draftFrom(r));
      announce = 'Routes saved';
      notice = 'Routes saved.';
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      saveError = e.error;
      if (e.error.status === 412) {
        await load();
        notice =
          'The routes changed while you were editing. The latest saved list is loaded; apply your changes again.';
      }
    } finally {
      saving = false;
    }
  }
</script>

{#if !admin}
  <EmptyState title="Administrator access needed">
    Routes decide which channel gets which alert, so only administrators can see or change them.
  </EmptyState>
{:else if failure}
  <FormError error={failure} />
{:else if !loaded}
  <p role="status">Loading…</p>
{:else}
  <p class="visually-hidden" role="status">{announce}</p>
  <div class="explain">
    <p>
      Alerts are checked against the routes from top to bottom. The first route that matches sends
      the alert to its channel and stops, unless "Keep looking" is on. A route with no filters
      matches every alert.
    </p>
    <p><strong>If no route matches, the alert is recorded but no notification is sent.</strong></p>
  </div>

  {#if channels.length === 0}
    <EmptyState title="Add a channel first">
      A route needs a channel to send to. Add one under <a href="/alerts/channels">Channels</a>.
    </EmptyState>
  {:else}
    <form onsubmit={save} novalidate aria-label="Routes">
      {#if saveError}<FormError error={saveError} />{/if}
      {#if notice}<p class="notice" role="status">{notice}</p>{/if}
      {#if errors.routes}<p class="error">{errors.routes}</p>{/if}

      {#if drafts.length === 0}
        <p class="empty">
          No routes yet, so no alert is sent. Add a route with no filters to send everything to one
          channel.
        </p>
      {/if}

      <ol>
        {#each drafts as r, i (r.key)}
          <li>
            <fieldset>
              <legend>Route {i + 1} of {drafts.length}</legend>
              <ChipInput
                id="route-{r.key}-tags"
                label="Tags (route {i + 1})"
                bind:tags={r.tags}
                error={errors[`routes[${i}].selector.tags`]}
                hint="Optional. Alerts for items with all of these tags match."
              />
              <CheckGroup
                id="route-{r.key}-severity"
                legend="Severity (route {i + 1})"
                options={severityOptions}
                bind:selected={r.severity}
                hint="Optional. None selected matches every severity."
              />
              <CheckGroup
                id="route-{r.key}-kinds"
                legend="Rule conditions (route {i + 1})"
                options={kindOptions}
                bind:selected={r.kinds}
                hint="Optional. None selected matches every condition."
              />
              <SelectField
                id="route-{r.key}-channel"
                label="Send to (route {i + 1})"
                bind:value={r.channelId}
                options={channelOptions}
                error={errors[`routes[${i}].channel_id`]}
              />
              <ToggleField
                id="route-{r.key}-continue"
                label="Keep looking after this route (route {i + 1})"
                bind:checked={r.cont}
                hint="Also send to later matching routes."
              />
              <div class="row-actions">
                <button
                  type="button"
                  id="route-{r.key}-up"
                  class="move"
                  disabled={i === 0}
                  aria-label="Move route {i + 1} up"
                  onclick={() => void shift(i, -1)}>Move up</button
                >
                <button
                  type="button"
                  id="route-{r.key}-down"
                  class="move"
                  disabled={i === drafts.length - 1}
                  aria-label="Move route {i + 1} down"
                  onclick={() => void shift(i, 1)}>Move down</button
                >
                <button
                  type="button"
                  class="move"
                  aria-label="Remove route {i + 1}"
                  onclick={() => remove(i)}>Remove</button
                >
              </div>
            </fieldset>
          </li>
        {/each}
      </ol>

      <div class="actions">
        <Button variant="secondary" disabled={drafts.length >= MAX_ROUTES} onclick={add}
          >Add route</Button
        >
        <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save routes'}</Button>
      </div>
    </form>
  {/if}
{/if}

<style>
  .explain {
    max-width: 60ch;
    margin-bottom: var(--space-4);
    color: var(--color-text-muted);
  }

  .explain p {
    margin: 0 0 var(--space-2);
  }

  .explain strong {
    color: var(--color-text);
  }

  form {
    display: grid;
    gap: var(--space-4);
    max-width: 48rem;
  }

  ol {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  fieldset {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
    min-width: 0;
  }

  legend {
    padding: 0 var(--space-2);
    font-weight: 700;
  }

  .row-actions,
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }

  .move {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font-weight: 600;
    cursor: pointer;
  }

  .move:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }

  .empty {
    margin: 0;
    color: var(--color-text-muted);
  }

  .error {
    margin: 0;
    color: var(--color-status-critical);
    font-weight: 600;
  }

  .notice {
    margin: 0;
    padding: var(--space-3);
    border: 1px solid var(--color-status-warning);
    border-radius: var(--radius-1);
    background: var(--color-status-warning-bg);
    color: var(--color-status-warning);
    font-weight: 600;
  }
</style>
