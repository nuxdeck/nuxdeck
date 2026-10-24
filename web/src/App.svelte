<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { auth } from './lib/auth.svelte';
  import AuthCard from './lib/ui/AuthCard.svelte';
  import Shell from './lib/ui/Shell.svelte';
  import Login from './routes/Login.svelte';
  import Setup from './routes/Setup.svelte';
  import Unreachable from './routes/Unreachable.svelte';

  onMount(() => {
    void auth.init();
  });

  const titles: Partial<Record<typeof auth.status, string>> = {
    loading: 'Loading',
    setup: 'Set up',
    anonymous: 'Sign in',
    unreachable: 'Cannot reach the server',
  };

  // The signed-in shell manages its own title and focus; the other screens do it here.
  let previous = auth.status;
  $effect(() => {
    const status = auth.status;
    const title = titles[status];
    if (title) document.title = `${title} · Nux Deck`;
    if (status !== previous && title && status !== 'loading') {
      void tick().then(() => document.getElementById('page-title')?.focus());
    }
    previous = status;
  });
</script>

{#if auth.status === 'loading'}
  <AuthCard title="Loading Nux Deck">
    <p role="status">Checking your session…</p>
  </AuthCard>
{:else if auth.status === 'setup'}
  <Setup />
{:else if auth.status === 'anonymous'}
  <Login />
{:else if auth.status === 'unreachable'}
  <Unreachable />
{:else}
  <Shell />
{/if}
