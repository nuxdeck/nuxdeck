<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    api,
    ApiRequestError,
    type ApiError,
    type Silence,
    type SilenceKind,
  } from '../api/client';
  import { formatTime } from '../format';
  import Button from '../ui/Button.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import FormError from '../ui/FormError.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import TextAreaField from '../ui/TextAreaField.svelte';
  import TextField from '../ui/TextField.svelte';
  import CheckGroup from './CheckGroup.svelte';
  import ChipInput from './ChipInput.svelte';
  import DateTimeField from './DateTimeField.svelte';
  import { canOperate, RULE_KINDS, SEVERITIES, selectorSummary } from './model';
  import {
    emptySilenceForm,
    MAX_LENGTH_DAYS,
    MAX_REASON,
    silenceFieldId,
    silenceInput,
    validateSilence,
    type SilenceErrors,
    type SilenceForm,
  } from './silences';

  const canWrite = $derived(canOperate());
  const fid = silenceFieldId;

  let items = $state<Silence[]>([]);
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  let actionError = $state<ApiError | null>(null);
  let showExpired = $state(false);
  let creating = $state(false);
  let form = $state<SilenceForm>(emptySilenceForm());
  let errors = $state<SilenceErrors>({});
  let saving = $state(false);
  let confirming = $state<string | null>(null);
  let announce = $state('');

  const kindOptions = [
    { value: 'silence', label: 'Silence (up to 30 days)' },
    { value: 'maintenance', label: 'Maintenance window (up to 90 days, may be scheduled)' },
  ];
  const severityOptions = SEVERITIES.map((s) => ({
    value: s,
    label: s.charAt(0).toUpperCase() + s.slice(1),
  }));
  const kindsOptions = RULE_KINDS.map((k) => ({ value: k.id, label: k.label }));
  const err = (p: string): string | undefined => errors[p];

  async function load(): Promise<void> {
    try {
      items = await api.silences(!showExpired);
      failure = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
    } finally {
      loaded = true;
    }
  }

  onMount(() => void load());

  function start(): void {
    form = emptySilenceForm();
    errors = {};
    actionError = null;
    creating = true;
    void tick().then(() => document.getElementById('silence-form-title')?.focus());
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    actionError = null;
    const found = validateSilence(form);
    errors = found;
    if (Object.keys(found).length > 0) {
      const first = Object.keys(found)[0] as string;
      await tick();
      document.getElementById(first === 'selector' ? fid('selector.tags') : fid(first))?.focus();
      return;
    }
    saving = true;
    try {
      await api.createSilence(silenceInput(form));
      creating = false;
      announce = form.kind === 'maintenance' ? 'Maintenance window created' : 'Silence created';
      await load();
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
      if (e.error.status === 422 && e.error.field) {
        errors = { [e.error.field]: e.error.message };
        await tick();
        document.getElementById(fid(e.error.field))?.focus();
      }
    } finally {
      saving = false;
    }
  }

  async function remove(s: Silence): Promise<void> {
    actionError = null;
    try {
      await api.deleteSilence(s.id);
      items = items.filter((x) => x.id !== s.id);
      confirming = null;
      announce = s.state === 'expired' ? 'Silence deleted' : 'Silence ended';
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
    }
  }

  const stateLabel = (s: Silence): string =>
    s.state === 'active' ? 'Active' : s.state === 'scheduled' ? 'Scheduled' : 'Expired';
</script>

<p class="visually-hidden" role="status">{announce}</p>

{#if creating}
  <h2 id="silence-form-title" tabindex="-1">New silence or maintenance window</h2>
  <form onsubmit={save} novalidate aria-labelledby="silence-form-title">
    {#if actionError}<FormError error={actionError} />{/if}
    <SelectField
      id={fid('kind')}
      label="Type"
      bind:value={() => form.kind, (v) => ((form.kind = v as SilenceKind), (errors = {}))}
      options={kindOptions}
      hint="Both stop notifications. Alerts still open and are recorded."
    />
    <fieldset>
      <legend>What to mute</legend>
      {#if err('selector')}
        <p id="{fid('selector')}-error" class="error" role="alert">{err('selector')}</p>
      {/if}
      <ChipInput
        id={fid('selector.tags')}
        label="Tags"
        bind:tags={form.tags}
        error={err('selector.tags')}
      />
      <TextAreaField
        id={fid('selector.ids')}
        label="Item IDs"
        bind:value={form.ids}
        error={err('selector.ids')}
        rows={2}
        hint="Optional. One 26-character ID per line or separated by commas."
      />
      <CheckGroup
        id={fid('severity')}
        legend="Severity"
        options={severityOptions}
        bind:selected={form.severity}
      />
      <CheckGroup
        id={fid('kinds')}
        legend="Rule conditions"
        options={kindsOptions}
        bind:selected={form.kinds}
      />
    </fieldset>
    <fieldset>
      <legend>When</legend>
      <div class="grid">
        <DateTimeField
          id={fid('starts_at')}
          label="Starts"
          bind:value={form.startsAt}
          error={err('starts_at')}
          hint="Leave blank to start now. At most one year ahead."
        />
        <DateTimeField
          id={fid('ends_at')}
          label="Ends"
          bind:value={form.endsAt}
          error={err('ends_at')}
          required
          hint="At most {MAX_LENGTH_DAYS[form.kind]} days after it starts."
        />
      </div>
      <TextField
        id={fid('reason')}
        label="Reason"
        bind:value={form.reason}
        error={err('reason')}
        required
        maxlength={MAX_REASON}
        placeholder="Database upgrade"
      />
    </fieldset>
    <div class="actions">
      <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Create'}</Button>
      <Button variant="secondary" onclick={() => (creating = false)}>Cancel</Button>
    </div>
  </form>
{:else}
  <div class="bar">
    <label class="check">
      <input
        type="checkbox"
        bind:checked={showExpired}
        onchange={() => {
          loaded = false;
          void load();
        }}
      />
      Show expired
    </label>
    {#if canWrite}
      <button type="button" class="button-link" onclick={start}>New silence</button>
    {/if}
  </div>

  {#if failure}
    <FormError error={failure} />
  {:else if !loaded}
    <p role="status">Loading…</p>
  {:else}
    {#if actionError}<FormError error={actionError} />{/if}
    {#if items.length === 0}
      <EmptyState title="No silences">
        A silence or maintenance window stops notifications for matching items while you work on
        them.
      </EmptyState>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <caption class="visually-hidden">Silences and maintenance windows</caption>
          <thead>
            <tr>
              <th scope="col">State</th>
              <th scope="col">Type</th>
              <th scope="col">Matches</th>
              <th scope="col">From</th>
              <th scope="col">Until</th>
              <th scope="col">Reason</th>
              {#if canWrite}<th scope="col"><span class="visually-hidden">Actions</span></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each items as s (s.id)}
              <tr>
                <td>{stateLabel(s)}</td>
                <td>{s.kind === 'maintenance' ? 'Maintenance' : 'Silence'}</td>
                <td class="wrap">{selectorSummary(s.selector)}</td>
                <td>{formatTime(s.starts_at)}</td>
                <td>{formatTime(s.ends_at)}</td>
                <td class="wrap" title={s.reason}>{s.reason}</td>
                {#if canWrite}
                  <td>
                    {#if confirming === s.id}
                      <button type="button" class="link danger" onclick={() => void remove(s)}
                        >Yes, {s.state === 'expired' ? 'delete' : 'end'} it</button
                      >
                      <button type="button" class="link" onclick={() => (confirming = null)}
                        >Cancel</button
                      >
                    {:else}
                      <button
                        type="button"
                        class="link"
                        aria-label="{s.state === 'expired' ? 'Delete' : 'End'} {s.reason}"
                        onclick={() => (confirming = s.id)}
                        >{s.state === 'expired' ? 'Delete' : 'End'}</button
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
  h2 {
    margin-bottom: var(--space-3);
    font-size: var(--font-size-lg);
  }

  h2:focus {
    outline: none;
  }

  form {
    display: grid;
    gap: var(--space-5);
    max-width: 48rem;
  }

  fieldset {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }

  legend {
    margin-bottom: var(--space-2);
    padding: 0;
    font-size: var(--font-size-md);
    font-weight: 700;
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
    gap: var(--space-3);
  }

  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--target-size);
  }

  .check input {
    width: 1.25rem;
    height: 1.25rem;
  }

  .button-link {
    cursor: pointer;
    font: inherit;
    font-weight: 600;
  }

  .error {
    margin: 0;
    color: var(--color-status-critical);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
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
