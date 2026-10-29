<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../api/client';
  import { auth } from '../auth.svelte';
  import { SETUP_PATH } from './onboarding';

  let unfinished = $state(false);

  // Only administrators can read settings; everyone else never sees the banner.
  onMount(async () => {
    if (!(auth.user?.roles.includes('admin') ?? false)) return;
    try {
      unfinished = !(await api.settings())['setup.completed'];
    } catch {
      unfinished = false; // a failed read must not block the page; the wizard reports its own errors
    }
  });
</script>

{#if unfinished}
  <aside class="banner" aria-labelledby="setup-banner-title">
    <p id="setup-banner-title">
      <strong>Setup is not finished.</strong> Set the server address and add your first host.
    </p>
    <a class="button-link" href={SETUP_PATH}>Continue setup</a>
  </aside>
{/if}

<style>
  .banner {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
  }

  p {
    margin: 0;
  }
</style>
