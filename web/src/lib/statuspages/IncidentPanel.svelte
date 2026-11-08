<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    api,
    ApiRequestError,
    type ApiError,
    type Incident,
    type IncidentImpact,
    type IncidentStatus,
  } from '../api/client';
  import Button from '../ui/Button.svelte';
  import IncidentRow from './IncidentRow.svelte';
  import FormError from '../ui/FormError.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import TextAreaField from '../ui/TextAreaField.svelte';
  import TextField from '../ui/TextField.svelte';
  import {
    INCIDENT_IMPACTS,
    INCIDENT_STATUSES,
    MAX_INCIDENT_BODY,
    MAX_INCIDENT_TITLE,
    canWriteStatusPages,
    textProblem,
  } from './form';

  interface Props {
    pageId: string;
    /** Called after any change so the public preview can reload. */
    onchange?: () => void;
  }

  let { pageId, onchange }: Props = $props();

  const canWrite = $derived(canWriteStatusPages());

  let items = $state<Incident[]>([]);
  let loaded = $state(false);
  let loadFailure = $state<ApiError | null>(null);
  let failure = $state<ApiError | null>(null);
  let announce = $state('');
  let saving = $state(false);

  let title = $state('');
  let body = $state('');
  let status = $state<string>('investigating');
  let impact = $state<string>('minor');
  let errors = $state<Record<string, string>>({});

  const statusOptions = INCIDENT_STATUSES.map((s) => ({ value: s.value, label: s.label }));
  const impactOptions = INCIDENT_IMPACTS.map((s) => ({ value: s.value, label: s.label }));

  async function load(): Promise<void> {
    try {
      items = await api.incidents(pageId);
      loadFailure = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      loadFailure = e.error;
    } finally {
      loaded = true;
    }
  }

  onMount(() => void load());

  function changed(message: string): void {
    announce = message;
    onchange?.();
  }

  async function run(action: () => Promise<void>): Promise<boolean> {
    failure = null;
    saving = true;
    try {
      await action();
      return true;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
      return false;
    } finally {
      saving = false;
    }
  }

  async function post(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const found: Record<string, string> = {};
    const t = textProblem(title, MAX_INCIDENT_TITLE, true);
    if (t) found.title = t;
    const b = textProblem(body.replace(/[\r\n]/g, ' '), MAX_INCIDENT_BODY, true);
    if (b) found.body = b;
    errors = found;
    if (Object.keys(found).length > 0) {
      await tick();
      document.getElementById(found.title ? 'inc-title' : 'inc-body')?.focus();
      return;
    }
    const ok = await run(async () => {
      const created = await api.createIncident(pageId, {
        title: title.trim(),
        body: body.trim(),
        status: status as IncidentStatus,
        impact: impact as IncidentImpact,
      });
      items = [created, ...items];
      title = '';
      body = '';
      changed(`Incident posted: ${created.title}`);
    });
    if (!ok) await tick();
  }

  async function update(inc: Incident, st: string, text: string): Promise<boolean> {
    return run(async () => {
      const next = await api.addIncidentUpdate(pageId, inc.id, {
        status: st as IncidentStatus,
        body: text,
      });
      items = items.map((i) => (i.id === inc.id ? next : i));
      changed(`Update added to ${inc.title}`);
    });
  }

  async function resolve(inc: Incident, text: string): Promise<boolean> {
    return run(async () => {
      const next = await api.resolveIncident(pageId, inc.id, text);
      items = items.map((i) => (i.id === inc.id ? next : i));
      changed(`Resolved: ${inc.title}`);
    });
  }

  async function remove(inc: Incident): Promise<boolean> {
    return run(async () => {
      await api.deleteIncident(pageId, inc.id);
      items = items.filter((i) => i.id !== inc.id);
      changed(`Deleted incident ${inc.title}`);
    });
  }
</script>

<section class="panel" aria-labelledby="incidents-title">
  <h2 id="incidents-title">Incidents</h2>
  <p class="hint">
    Incident notes are plain text and appear on the public page. Do not include hostnames, addresses
    or other internal details.
  </p>
  <p class="visually-hidden" role="status">{announce}</p>

  {#if failure}<FormError error={failure} />{/if}

  {#if canWrite}
    <form class="composer" onsubmit={post} novalidate aria-label="Post an incident">
      <TextField
        id="inc-title"
        label="Title"
        bind:value={title}
        error={errors.title}
        maxlength={MAX_INCIDENT_TITLE}
        required
      />
      <TextAreaField
        id="inc-body"
        label="What is happening"
        bind:value={body}
        error={errors.body}
        maxlength={MAX_INCIDENT_BODY}
        required
      />
      <div class="pair">
        <SelectField id="inc-status" label="Status" bind:value={status} options={statusOptions} />
        <SelectField id="inc-impact" label="Impact" bind:value={impact} options={impactOptions} />
      </div>
      <div><Button type="submit" disabled={saving}>Post incident</Button></div>
    </form>
  {/if}

  {#if loadFailure}
    <FormError error={loadFailure} />
  {:else if !loaded}
    <p role="status">Loading…</p>
  {:else if items.length === 0}
    <p class="hint">No incidents posted.</p>
  {:else}
    <ul class="list">
      {#each items as inc (inc.id)}
        <IncidentRow
          {inc}
          {canWrite}
          busy={saving}
          onupdate={update}
          onresolve={resolve}
          ondelete={remove}
        />
      {/each}
    </ul>
  {/if}
</section>

<style>
  .panel {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
  }

  h2 {
    font-size: var(--font-size-lg);
  }

  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .composer {
    display: grid;
    gap: var(--space-3);
  }

  .pair {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
    gap: var(--space-3);
  }

  .list {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }
</style>
