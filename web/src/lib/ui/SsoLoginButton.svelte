<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import { ssoErrorMessage } from '../sso';

  let enabled = $state(false);
  let failure = $state<string | null>(null);

  onMount(() => {
    const code = new URLSearchParams(window.location.search).get('sso_error');
    if (code) failure = ssoErrorMessage(code);
    // The button is optional: when the status cannot be read, the password form still works.
    api
      .oidcStatus()
      .then((s) => (enabled = s.enabled))
      .catch(() => (enabled = false));
  });
</script>

{#if failure}<p class="sso-error" role="alert">{failure}</p>{/if}
{#if enabled}
  <a class="sso" href="/api/v1/auth/oidc/start">Sign in with single sign-on</a>
{/if}

<style>
  .sso {
    display: block;
    text-align: center;
    padding: var(--space-2) var(--space-4);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    color: inherit;
  }

  .sso-error {
    margin: 0;
  }
</style>
