<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Settings } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import AddressStep from '../lib/onboarding/AddressStep.svelte';
  import DoneStep from '../lib/onboarding/DoneStep.svelte';
  import HostStep from '../lib/onboarding/HostStep.svelte';
  import TelemetryStep from '../lib/onboarding/TelemetryStep.svelte';
  import { resumeStep, WIZARD_STEPS, type WizardStepId } from '../lib/onboarding/onboarding';
  import { inventory } from '../lib/inventory.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';

  let settings = $state<Settings | null>(null);
  let step = $state<WizardStepId | null>(null);
  let loadFailure = $state<ApiError | null>(null);
  let finishFailure = $state<ApiError | null>(null);
  let finishing = $state(false);
  let previousStep: WizardStepId | null = null;

  const isAdmin = $derived(auth.user?.roles.includes('admin') ?? false);
  const position = $derived(step ? WIZARD_STEPS.findIndex((s) => s.id === step) : -1);

  onMount(() => {
    if (!isAdmin) return;
    void load();
  });

  async function load(): Promise<void> {
    try {
      const current = await api.settings();
      settings = current;
      step = current['setup.completed'] ? 'done' : resumeStep(current['server.public_url']);
    } catch (e) {
      loadFailure = e instanceof ApiRequestError ? e.error : null;
    }
  }

  // Each step change moves focus to the new step heading, so a keyboard or screen reader user
  // starts at the new content instead of the top of the page (WCAG 2.4.3).
  $effect(() => {
    const current = step;
    if (current === null || current === previousStep) return;
    previousStep = current;
    void tick().then(() => document.getElementById('wizard-step-title')?.focus());
  });

  function go(to: WizardStepId): void {
    step = to;
  }

  function back(): void {
    const previous = WIZARD_STEPS[position - 1];
    if (previous) go(previous.id);
  }

  function next(): void {
    const following = WIZARD_STEPS[position + 1];
    if (following) go(following.id);
  }

  async function finish(): Promise<void> {
    finishing = true;
    finishFailure = null;
    try {
      settings = await api.setSetupCompleted(true);
      go('done');
    } catch (e) {
      finishFailure = e instanceof ApiRequestError ? e.error : null;
    } finally {
      finishing = false;
    }
  }
</script>

<h1 id="page-title" tabindex="-1">Set up Nux Deck</h1>

{#if !isAdmin}
  <EmptyState title="Administrators only">
    Ask an administrator to finish the setup of this server.
  </EmptyState>
{:else if loadFailure}
  <FormError error={loadFailure} />
{:else if step === null}
  <p role="status">Loading the setup…</p>
{:else}
  <ol class="progress" aria-label="Setup progress">
    <li>
      Step 1: Create administrator <span class="visually-hidden">(done)</span>
    </li>
    {#each WIZARD_STEPS as s, i (s.id)}
      <li aria-current={s.id === step ? 'step' : undefined} class:current={s.id === step}>
        Step {i + 2}: {s.title}
        <span class="visually-hidden"
          >{i < position ? '(done)' : s.id === step ? '(current)' : ''}</span
        >
      </li>
    {/each}
  </ol>
  <p class="position">
    Step {position + 2} of {WIZARD_STEPS.length + 1}. Every step can be skipped and changed later in
    Settings.
  </p>

  {#if finishFailure}<FormError error={finishFailure} />{/if}

  <section class="step" aria-label="Current step">
    {#if step === 'address'}
      <AddressStep
        initial={settings?.['server.public_url'] || window.location.origin}
        onNext={next}
        onSkip={next}
      />
    {:else if step === 'telemetry'}
      <TelemetryStep
        initialEnabled={settings?.['telemetry.enabled'] ?? false}
        locked={settings?.['telemetry.locked'] ?? false}
        onNext={next}
        onBack={back}
        onSkip={next}
      />
    {:else if step === 'host'}
      <HostStep onFinish={finish} onBack={back} busy={finishing} />
    {:else}
      <DoneStep hostsConnected={inventory.hosts.length > 0} />
    {/if}
  </section>
{/if}

<style>
  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
    margin-bottom: var(--space-4);
  }

  h1:focus {
    outline: none;
  }

  .progress {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2) var(--space-4);
    margin: 0 0 var(--space-2);
    padding: 0;
    list-style: none;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }

  .progress .current {
    color: var(--color-text);
    font-weight: 600;
    text-decoration: underline;
  }

  .position {
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    margin-bottom: var(--space-6);
  }

  .step {
    display: grid;
    gap: var(--space-4);
  }
</style>
