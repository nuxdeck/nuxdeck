<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { api, ApiRequestError, type ApiError } from '../api/client';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';
  import FormError from '../ui/FormError.svelte';
  import { normalizedPublicUrl, publicUrlProblem } from './onboarding';

  interface Props {
    /** The saved address, or the address the administrator reached this page on. */
    initial: string;
    onNext: () => void;
    onSkip: () => void;
  }

  let { initial, onNext, onSkip }: Props = $props();

  // Captured once: the field is the administrator's edit, not a live mirror of the prop.
  // svelte-ignore state_referenced_locally
  let address = $state(initial);
  let busy = $state(false);
  let problem = $state<string | null>(null);
  let failure = $state<ApiError | null>(null);

  const addressError = $derived(
    problem ?? (failure?.field === 'value' ? `${failure.message} ${failure.hint}` : undefined),
  );

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    problem = publicUrlProblem(address);
    failure = null;
    if (problem) return;
    busy = true;
    try {
      await api.setPublicUrl(normalizedPublicUrl(address));
      onNext();
    } catch (e) {
      failure = e instanceof ApiRequestError ? e.error : null;
    } finally {
      busy = false;
    }
  }
</script>

<h2 id="wizard-step-title" tabindex="-1">Server address</h2>
<p class="intro">
  Agents and browsers reach Nux Deck at this address. It goes into every install command, so use the
  one your people and hosts can open.
</p>

<form onsubmit={save} class="step">
  {#if failure && failure.field !== 'value'}<FormError error={failure} />{/if}
  <Field
    id="public-url"
    label="Public address"
    type="text"
    bind:value={address}
    autocomplete="url"
    disabled={busy}
    hint="Scheme and host, with a port if you use one. No path."
    error={addressError}
  />
  <div class="actions">
    <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save and continue'}</Button>
    <Button variant="secondary" onclick={onSkip}>Skip for now</Button>
  </div>
</form>

<style>
  .intro {
    color: var(--color-text-muted);
  }

  .step {
    display: grid;
    gap: var(--space-4);
    max-width: 60ch;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
  }
</style>
