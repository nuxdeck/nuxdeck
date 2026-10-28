<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type RuleKind, type Severity } from '../api/client';
  import Button from '../ui/Button.svelte';
  import FormError from '../ui/FormError.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import TextAreaField from '../ui/TextAreaField.svelte';
  import TextField from '../ui/TextField.svelte';
  import ToggleField from '../ui/ToggleField.svelte';
  import ChipInput from './ChipInput.svelte';
  import { RULE_KINDS, SEVERITIES } from './model';
  import {
    emptyRuleForm,
    formFromRule,
    ruleFieldId,
    ruleInput,
    validateRule,
    type RuleErrors,
    type RuleForm,
  } from './rules';

  interface Props {
    /** The rule being edited; absent when creating. */
    id?: string;
    onclose: (saved: boolean) => void;
  }

  let { id, onclose }: Props = $props();

  const editing = $derived(id !== undefined);

  let form = $state<RuleForm>(emptyRuleForm());
  let etag = $state('');
  let loading = $state(false);
  let loadError = $state<ApiError | null>(null);
  let saving = $state(false);
  let errors = $state<RuleErrors>({});
  let failure = $state<ApiError | null>(null);
  let notice = $state('');

  const kindOptions = RULE_KINDS.map((k) => ({ value: k.id, label: k.label }));
  const severityOptions = SEVERITIES.map((s) => ({
    value: s,
    label: s.charAt(0).toUpperCase() + s.slice(1),
  }));
  const modeOptions = [
    { value: 'either', label: 'Stopped or restarting repeatedly' },
    { value: 'stopped', label: 'Stopped (exited or dead)' },
    { value: 'restart_loop', label: 'Restarting repeatedly' },
  ];
  const targetOptions = [
    { value: 'host', label: 'Hosts' },
    { value: 'container', label: 'Containers' },
  ];
  const metricOptions = $derived([
    { value: 'cpu', label: 'CPU' },
    { value: 'memory', label: 'Memory' },
    ...(form.target === 'host' ? [{ value: 'disk', label: 'Disk' }] : []),
  ]);

  const err = (path: string): string | undefined => errors[path];
  const fid = ruleFieldId;

  async function load(): Promise<void> {
    if (!id) return;
    loading = true;
    loadError = null;
    try {
      const r = await api.rule(id);
      form = formFromRule(r.rule);
      etag = r.etag;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      loadError = e.error;
    } finally {
      loading = false;
    }
  }

  onMount(() => void load());

  async function focusFirst(path: string): Promise<void> {
    await tick();
    document.getElementById(fid(path))?.focus();
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    failure = null;
    notice = '';
    const found = validateRule(form);
    if (Object.keys(found).length > 0) {
      errors = found;
      const first = Object.keys(found)[0] as string;
      await focusFirst(first);
      return;
    }
    errors = {};
    saving = true;
    try {
      if (editing && id) await api.updateRule(id, ruleInput(form), etag);
      else await api.createRule(ruleInput(form));
      onclose(true);
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
      if (e.error.status === 422 && e.error.field) {
        errors = { [e.error.field]: e.error.message };
        await focusFirst(e.error.field);
      } else if (e.error.status === 412 && id) {
        await load();
        notice =
          'This rule changed while you were editing. The latest saved version is loaded; apply your changes again.';
      }
    } finally {
      saving = false;
    }
  }

  const title = $derived(editing ? 'Edit rule' : 'Add rule');
</script>

<h2 id="rule-editor-title" tabindex="-1">{title}</h2>

{#if loadError}
  <FormError error={loadError} />
{:else if loading}
  <p role="status">Loading…</p>
{:else}
  <form onsubmit={save} novalidate aria-labelledby="rule-editor-title">
    {#if failure}<FormError error={failure} />{/if}
    {#if notice}<p class="notice" role="status">{notice}</p>{/if}

    <fieldset>
      <legend>When to alert</legend>
      <TextField
        id={fid('name')}
        label="Name"
        bind:value={form.name}
        error={err('name')}
        required
        maxlength={100}
        placeholder="Production hosts offline"
      />
      <SelectField
        id={fid('kind')}
        label="Condition"
        bind:value={() => form.kind, (v) => ((form.kind = v as RuleKind), (errors = {}))}
        options={kindOptions}
        disabled={editing}
        hint={editing
          ? 'The condition cannot be changed. Create a new rule to alert on something else.'
          : undefined}
      />
      <SelectField
        id={fid('severity')}
        label="Severity"
        bind:value={() => form.severity, (v) => (form.severity = v as Severity)}
        options={severityOptions}
      />

      {#if form.kind === 'container_stopped'}
        <SelectField
          id={fid('params.mode')}
          label="Alert when a container is"
          bind:value={form.mode}
          options={modeOptions}
          error={err('params.mode')}
        />
        {#if form.mode !== 'stopped'}
          <div class="grid">
            <TextField
              id={fid('params.restarts')}
              label="Restarts"
              bind:value={form.restarts}
              error={err('params.restarts')}
              inputmode="numeric"
              hint="2 to 100 restarts."
            />
            <TextField
              id={fid('params.window_s')}
              label="Within (seconds)"
              bind:value={form.windowS}
              error={err('params.window_s')}
              inputmode="numeric"
              hint="60 to 3600 seconds."
            />
          </div>
        {/if}
      {:else if form.kind === 'metric_threshold'}
        <div class="grid">
          <SelectField
            id={fid('params.target')}
            label="Applies to"
            bind:value={form.target}
            options={targetOptions}
            error={err('params.target')}
            onchange={() => {
              if (form.target !== 'host' && form.metric === 'disk') form.metric = 'cpu';
            }}
          />
          <SelectField
            id={fid('params.metric')}
            label="Metric"
            bind:value={form.metric}
            options={metricOptions}
            error={err('params.metric')}
            hint={form.target === 'container'
              ? 'Disk usage is only available for hosts.'
              : undefined}
          />
          <TextField
            id={fid('params.threshold')}
            label="Above (percent)"
            bind:value={form.threshold}
            error={err('params.threshold')}
            inputmode="decimal"
            required
            hint="Greater than 0, up to 100."
          />
        </div>
      {:else if form.kind === 'tls_expiring'}
        <TextField
          id={fid('params.days')}
          label="Days before expiry"
          bind:value={form.days}
          error={err('params.days')}
          inputmode="numeric"
          required
          hint="1 to 825 days."
        />
      {/if}

      <TextField
        id={fid('params.for_s')}
        label="Must hold for (seconds)"
        bind:value={form.forS}
        error={err('params.for_s')}
        inputmode="numeric"
        hint="0 to 86400. The condition must last this long before an alert opens. Leave blank for the default (300 for metrics, otherwise 0)."
      />
    </fieldset>

    <fieldset>
      <legend>What it applies to</legend>
      <p class="hint">Leave both empty to apply to every matching item.</p>
      <ChipInput
        id={fid('selector.tags')}
        label="Tags"
        bind:tags={form.tags}
        error={err('selector.tags')}
        hint="Items need all of these tags. Checks have no tags, so use item IDs for them."
      />
      <TextAreaField
        id={fid('selector.ids')}
        label="Item IDs"
        bind:value={form.ids}
        error={err('selector.ids')}
        rows={2}
        hint="Optional. One 26-character ID per line or separated by commas, up to 50."
      />
    </fieldset>

    <ToggleField
      id={fid('enabled')}
      label="Enabled"
      bind:checked={form.enabled}
      hint="A disabled rule opens no alerts."
    />

    <div class="actions">
      <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save rule'}</Button>
      <Button variant="secondary" onclick={() => onclose(false)}>Cancel</Button>
    </div>
  </form>
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
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: var(--space-3);
  }

  .hint {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
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

  .actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }
</style>
