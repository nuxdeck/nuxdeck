<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { api, ApiRequestError, type ApiError, type EnrollmentToken } from '../lib/api/client';
  import { linuxInstallCommand } from '../lib/agentCommand';
  import { formatTime } from '../lib/format';
  import { inventory } from '../lib/inventory.svelte';
  import Button from '../lib/ui/Button.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import Icon from '../lib/ui/Icon.svelte';

  let token = $state<EnrollmentToken | null>(null);
  let creating = $state(false);
  let failure = $state<ApiError | null>(null);
  let expired = $state(false);
  let copied = $state<'' | 'copied' | 'failed'>('');
  // Hosts that existed when the token was made: the agent we are waiting for is the first one not in this set.
  let knownHosts = new Set<string>();
  let expiryTimer: ReturnType<typeof setTimeout> | undefined;

  const command = $derived(token ? linuxInstallCommand(token.token) : '');
  const arrived = $derived(
    token ? inventory.hosts.find((h) => !knownHosts.has(h.id) && h.status === 'online') : undefined,
  );

  async function create(): Promise<void> {
    creating = true;
    failure = null;
    copied = '';
    try {
      const created = await api.createEnrollmentToken();
      knownHosts = new Set(inventory.hosts.map((h) => h.id));
      expired = false;
      clearTimeout(expiryTimer);
      const left = new Date(created.expires_at).getTime() - Date.now();
      expiryTimer = setTimeout(() => (expired = true), Math.max(left, 0));
      token = created;
    } catch (e) {
      failure = e instanceof ApiRequestError ? e.error : null;
    } finally {
      creating = false;
    }
  }

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(command);
      copied = 'copied';
    } catch {
      copied = 'failed'; // the text is selectable below, so the reader can copy it by hand
    }
  }

  onDestroy(() => clearTimeout(expiryTimer));
</script>

<h1 id="page-title" tabindex="-1">Add a host</h1>
<p class="question">Run one command on the machine you want to watch.</p>

<ol class="steps">
  <li>
    <h2>1. Create a one-time token</h2>
    <p>
      The token lets one agent enrol. It works once, expires after an hour and is shown only on this
      page.
    </p>
    {#if failure}
      <FormError error={failure} />
    {/if}
    <Button onclick={create} disabled={creating}>
      {token ? 'Create a new token' : 'Create token'}
    </Button>
  </li>

  {#if token}
    <li>
      <h2>2. Run this on the host</h2>
      <p>
        Needs a Linux machine with systemd and root access. The agent installs as an unprivileged
        user and only connects out to this server.
      </p>
      <pre class="command"><code id="install-command">{command}</code></pre>
      <div class="actions">
        <Button variant="secondary" onclick={copy}>
          <Icon name="copy" size={16} /> Copy command
        </Button>
        <span role="status">
          {#if copied === 'copied'}Copied to the clipboard.{/if}
          {#if copied === 'failed'}Copying was blocked. Select the command above and copy it.{/if}
        </span>
      </div>
      <p class="expiry">
        {#if expired}
          This token has expired. Create a new one to continue.
        {:else}
          Expires {formatTime(token.expires_at)}.
        {/if}
      </p>
    </li>

    <li>
      <h2>3. Wait for it to connect</h2>
      <div class="wait" role="status">
        {#if arrived}
          <Icon name="checkCircle" />
          <span>Connected: <strong>{arrived.hostname}</strong></span>
        {:else if expired}
          <Icon name="xCircle" />
          <span>The token expired before an agent connected.</span>
        {:else if inventory.status === 'failed'}
          <Icon name="alertTriangle" />
          <span>Live updates are unavailable. Reload this page after running the command.</span>
        {:else}
          <Icon name="circle" />
          <span>Waiting for the agent to connect…</span>
        {/if}
      </div>
      {#if arrived}
        <p class="next">
          <a class="button-link" href="/inventory/hosts/{arrived.id}">Open {arrived.hostname}</a>
          <a href="/inventory">Back to the inventory</a>
        </p>
      {/if}
    </li>
  {/if}
</ol>

<style>
  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  h2 {
    font-size: var(--font-size-md);
  }

  .question {
    margin: var(--space-1) 0 var(--space-6);
    color: var(--color-text-muted);
  }

  .steps {
    display: grid;
    gap: var(--space-6);
    max-width: 72ch;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: grid;
    gap: var(--space-3);
    justify-items: start;
  }

  li > p {
    color: var(--color-text-muted);
  }

  .command {
    max-width: 100%;
    margin: 0;
    padding: var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
    font-size: var(--font-size-sm);
    line-height: var(--line-height-log);
  }

  .command code {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-3);
  }

  .expiry {
    font-size: var(--font-size-sm);
  }

  .wait {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
    background: var(--color-surface);
  }

  .next {
    display: flex;
    align-items: center;
    gap: var(--space-4);
  }
</style>
