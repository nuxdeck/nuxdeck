<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Settings } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import ToggleField from '../lib/ui/ToggleField.svelte';
  import SsoSettings from '../lib/ui/SsoSettings.svelte';

  let settings = $state<Settings | null>(null);
  let payload = $state('');
  let enabled = $state(false);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  const isAdmin = $derived(auth.user?.roles.includes('admin') ?? false);

  async function load() {
    try {
      settings = await api.settings();
      enabled = settings['telemetry.enabled'];
      payload = JSON.stringify(await api.telemetryPreview(), null, 2);
      error = null;
    } catch (e) {
      if (e instanceof ApiRequestError) error = e.error;
    }
  }

  async function toggle() {
    busy = true;
    try {
      settings = await api.setTelemetryEnabled(enabled);
      error = null;
      payload = JSON.stringify(await api.telemetryPreview(), null, 2);
    } catch (e) {
      enabled = !enabled;
      if (e instanceof ApiRequestError) error = e.error;
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    if (isAdmin) void load();
  });
</script>

<h1>Settings</h1>

{#if !isAdmin}
  <p>Only administrators can change settings.</p>
{:else}
  <section aria-labelledby="telemetry-heading">
    <h2 id="telemetry-heading">Telemetry</h2>
    <p>
      Off until you turn it on. When on, nuxd sends one small diagnostic report a day with versions,
      rough scale buckets and error codes. Nothing identifies a person, a company or your
      infrastructure. This is exactly what would be sent.
    </p>
    {#if error}<FormError {error} />{/if}
    {#if settings}
      <ToggleField
        id="telemetry-enabled"
        label="Send the daily diagnostic report"
        hint={settings['telemetry.locked']
          ? 'Locked off by NUX_TELEMETRY=off on the server.'
          : 'Turning it off deletes the install ID.'}
        bind:checked={enabled}
        disabled={busy || settings['telemetry.locked']}
        onchange={toggle}
      />
    {/if}
    {#if payload}
      <h3 id="payload-heading">Next report</h3>
      <!-- A scrollable block must be keyboard-reachable (WCAG 2.1.1). -->
      <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
      <pre aria-labelledby="payload-heading" tabindex="0"><code>{payload}</code></pre>
    {/if}
  </section>

  <SsoSettings />
{/if}

<style>
  section {
    display: grid;
    gap: var(--space-3);
    max-width: 48rem;
  }

  pre {
    margin: 0;
    padding: var(--space-3);
    overflow: auto;
    max-height: 24rem;
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }
</style>
