<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { Incident } from '../api/client';
  import { formatTime } from '../format';
  import Button from '../ui/Button.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import TextAreaField from '../ui/TextAreaField.svelte';
  import { INCIDENT_STATUSES, MAX_INCIDENT_BODY, textProblem } from './form';

  interface Props {
    inc: Incident;
    canWrite: boolean;
    busy: boolean;
    /** Each handler resolves to true when the server accepted the change. */
    onupdate: (inc: Incident, status: string, body: string) => Promise<boolean>;
    onresolve: (inc: Incident, body: string) => Promise<boolean>;
    ondelete: (inc: Incident) => Promise<boolean>;
  }

  let { inc, canWrite, busy, onupdate, onresolve, ondelete }: Props = $props();

  const labelOf = (s: string): string => INCIDENT_STATUSES.find((o) => o.value === s)?.label ?? s;
  const statusOptions = INCIDENT_STATUSES.map((s) => ({ value: s.value, label: s.label }));

  let status = $state('monitoring');
  let body = $state('');
  let error = $state<string | undefined>();

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    error = textProblem(body.replace(/[\r\n]/g, ' '), MAX_INCIDENT_BODY, status !== 'resolved');
    if (error) return;
    if (await onupdate(inc, status, body.trim())) body = '';
  }

  async function resolve(): Promise<void> {
    error = textProblem(body.replace(/[\r\n]/g, ' '), MAX_INCIDENT_BODY, false);
    if (error) return;
    if (await onresolve(inc, body.trim())) body = '';
  }
</script>

<li class="incident">
  <h3>{inc.title}</h3>
  <p class="meta">
    {labelOf(inc.status)}, {inc.impact} impact, started {formatTime(
      inc.created_at,
    )}{#if inc.resolved_at}, resolved
      {formatTime(inc.resolved_at)}{/if}
  </p>
  <ol class="timeline" aria-label="Updates to {inc.title}">
    {#each inc.updates as u (u.at + u.status + u.body)}
      <li>
        <strong>{labelOf(u.status)}</strong>
        <span class="meta">{formatTime(u.at)}</span>
        {#if u.body}<p class="text">{u.body}</p>{/if}
      </li>
    {/each}
  </ol>
  {#if canWrite}
    <form class="update" onsubmit={submit} novalidate aria-label="Update {inc.title}">
      <SelectField
        id="upd-{inc.id}-status"
        label="New status"
        bind:value={status}
        options={statusOptions}
      />
      <TextAreaField
        id="upd-{inc.id}-body"
        label="Update"
        bind:value={body}
        {error}
        rows={2}
        maxlength={MAX_INCIDENT_BODY}
      />
      <div class="actions">
        <Button type="submit" variant="secondary" disabled={busy}>Add update</Button>
        {#if inc.status !== 'resolved'}
          <Button variant="secondary" disabled={busy} onclick={() => void resolve()}>Resolve</Button
          >
        {/if}
        <Button variant="secondary" disabled={busy} onclick={() => void ondelete(inc)}
          >Delete</Button
        >
      </div>
    </form>
  {/if}
</li>

<style>
  h3 {
    font-size: var(--font-size-md);
  }

  .meta {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .incident {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
  }

  .timeline {
    display: grid;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .update {
    display: grid;
    gap: var(--space-3);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .text {
    margin: 0;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
</style>
