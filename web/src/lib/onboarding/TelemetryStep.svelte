<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiRequestError, type ApiError } from '../api/client';
  import Button from '../ui/Button.svelte';
  import FormError from '../ui/FormError.svelte';
  import ToggleField from '../ui/ToggleField.svelte';

  interface Props {
    /** The saved choice; the server default is off. */
    initialEnabled: boolean;
    /** True when NUX_TELEMETRY=off fixes the choice on the server. */
    locked: boolean;
    onNext: () => void;
    onBack: () => void;
    onSkip: () => void;
  }

  let { initialEnabled, locked, onNext, onBack, onSkip }: Props = $props();

  // svelte-ignore state_referenced_locally
  let enabled = $state(initialEnabled);
  let preview = $state('');
  let previewFailed = $state(false);
  let busy = $state(false);
  let failure = $state<ApiError | null>(null);

  onMount(async () => {
    try {
      preview = JSON.stringify(await api.telemetryPreview(), null, 2);
    } catch {
      previewFailed = true;
    }
  });

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    failure = null;
    if (locked || enabled === initialEnabled) {
      onNext();
      return;
    }
    busy = true;
    try {
      await api.setTelemetryEnabled(enabled);
      onNext();
    } catch (e) {
      failure = e instanceof ApiRequestError ? e.error : null;
    } finally {
      busy = false;
    }
  }
</script>

<h2 id="wizard-step-title" tabindex="-1">Telemetry</h2>
<p class="intro">
  Telemetry is off unless you turn it on. When it is on, Nux Deck sends one small diagnostic report
  a day so the project can see which versions break. Nothing identifies a person, a company or your
  infrastructure.
</p>

<form onsubmit={save} class="step">
  {#if failure}<FormError error={failure} />{/if}
  <ToggleField
    id="telemetry-choice"
    label="Send the daily diagnostic report"
    hint={locked
      ? 'Switched off by NUX_TELEMETRY=off on the server.'
      : 'Leave this off to send nothing. You can change it later in Settings.'}
    bind:checked={enabled}
    disabled={busy || locked}
  />

  <h3 id="telemetry-report-heading">The exact report</h3>
  {#if previewFailed}
    <p role="status">The report preview could not be loaded. You can still choose.</p>
  {:else if preview}
    <!-- A scrollable block must be keyboard-reachable (WCAG 2.1.1). -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <pre aria-labelledby="telemetry-report-heading" tabindex="0"><code>{preview}</code></pre>
  {:else}
    <p role="status">Loading the report…</p>
  {/if}

  <div class="actions">
    <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save and continue'}</Button>
    <Button variant="secondary" onclick={onBack}>Back</Button>
    <Button variant="secondary" onclick={onSkip}>Skip for now</Button>
  </div>
</form>

<style>
  .intro {
    color: var(--color-text-muted);
    max-width: 62ch;
  }

  .step {
    display: grid;
    gap: var(--space-4);
    max-width: 72ch;
  }

  pre {
    max-height: 20rem;
    overflow: auto;
    margin: 0;
    padding: var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
    font-size: var(--font-size-sm);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
  }
</style>
