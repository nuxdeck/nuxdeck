<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Channel } from '../api/client';
  import { formatTime } from '../format';
  import EmptyState from '../ui/EmptyState.svelte';
  import FormError from '../ui/FormError.svelte';
  import ChannelEditor from './ChannelEditor.svelte';
  import { lastSendText, typeLabel } from './channels';
  import { describeAlertError, testFailureText } from './errors';
  import { isAdmin } from './model';

  const admin = $derived(isAdmin());

  let items = $state<Channel[]>([]);
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  let actionError = $state<ApiError | null>(null);
  let editing = $state<string | null | undefined>(undefined);
  let confirming = $state<string | null>(null);
  let testing = $state<Record<string, boolean>>({});
  // The outcome of the last test per channel: ok, or the failure text with its ALR-SEND code.
  let testResult = $state<Record<string, { ok: boolean; text: string }>>({});
  let announce = $state('');

  async function load(): Promise<void> {
    try {
      items = await api.channels();
      failure = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
    } finally {
      loaded = true;
    }
  }

  onMount(() => {
    if (admin) void load();
  });

  async function test(c: Channel): Promise<void> {
    testing = { ...testing, [c.id]: true };
    try {
      await api.testChannel(c.id);
      testResult = { ...testResult, [c.id]: { ok: true, text: `Test message sent to ${c.name}.` } };
      announce = `Test message sent to ${c.name}`;
      await load();
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      const { code, message, hint } = e.error;
      const text = describeAlertError(code)
        ? testFailureText(code, message, hint)
        : `${code} ${message} ${hint}`;
      testResult = { ...testResult, [c.id]: { ok: false, text } };
      announce = `Test to ${c.name} failed: ${code}`;
      if (e.error.status === 502) await load();
    } finally {
      testing = { ...testing, [c.id]: false };
    }
  }

  async function remove(c: Channel): Promise<void> {
    actionError = null;
    try {
      await api.deleteChannel(c.id);
      items = items.filter((x) => x.id !== c.id);
      confirming = null;
      announce = `Deleted channel ${c.name}`;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      actionError = e.error;
    }
  }

  async function closeEditor(saved: boolean): Promise<void> {
    editing = undefined;
    if (saved) announce = 'Channel saved';
    await load();
    await tick();
    document.getElementById('page-title')?.focus();
  }
</script>

<p class="visually-hidden" role="status">{announce}</p>

{#if !admin}
  <EmptyState title="Administrator access needed">
    Notification channels hold credentials, so only administrators can see or change them. Ask an
    administrator to set one up.
  </EmptyState>
{:else if editing !== undefined}
  {#key editing}
    <ChannelEditor id={editing ?? undefined} onclose={(saved) => void closeEditor(saved)} />
  {/key}
{:else}
  <div class="bar">
    <p class="intro">
      Channels are where notifications go. Routes choose which alerts use which channel.
    </p>
    <button type="button" class="button-link" onclick={() => (editing = null)}>Add channel</button>
  </div>

  {#if failure}
    <FormError error={failure} />
  {:else if !loaded}
    <p role="status">Loading…</p>
  {:else}
    {#if actionError}<FormError error={actionError} />{/if}
    {#if items.length === 0}
      <EmptyState title="No channels yet">
        Add a channel, then a route, or alerts will be recorded but never sent.
      </EmptyState>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <caption class="visually-hidden">Notification channels</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Type</th>
              <th scope="col">Enabled</th>
              <th scope="col">Last send</th>
              <th scope="col"><span class="visually-hidden">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {#each items as c (c.id)}
              <tr>
                <th scope="row" class="name">{c.name}</th>
                <td>{typeLabel(c.type)}</td>
                <td>{c.enabled ? 'Yes' : 'No'}</td>
                <td>
                  {lastSendText(c)}{#if c.last_sent_at}, {formatTime(c.last_sent_at)}{/if}
                </td>
                <td>
                  {#if confirming === c.id}
                    <span>Delete {c.name}?</span>
                    <button type="button" class="link danger" onclick={() => void remove(c)}
                      >Yes, delete</button
                    >
                    <button type="button" class="link" onclick={() => (confirming = null)}
                      >Cancel</button
                    >
                  {:else}
                    <button
                      type="button"
                      class="link"
                      disabled={testing[c.id]}
                      aria-label="Send test to {c.name}"
                      onclick={() => void test(c)}
                      >{testing[c.id] ? 'Sending…' : 'Send test'}</button
                    >
                    <button
                      type="button"
                      class="link"
                      aria-label="Edit {c.name}"
                      onclick={() => (editing = c.id)}>Edit</button
                    >
                    <button
                      type="button"
                      class="link"
                      aria-label="Delete {c.name}"
                      onclick={() => (confirming = c.id)}>Delete</button
                    >
                  {/if}
                </td>
              </tr>
              {#if testResult[c.id]}
                <tr>
                  <td colspan="5" class="result" class:fail={!testResult[c.id]?.ok}>
                    <p role={testResult[c.id]?.ok ? 'status' : 'alert'}>{testResult[c.id]?.text}</p>
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
{/if}

<style>
  .bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  .intro {
    margin: 0;
    color: var(--color-text-muted);
  }

  .button-link {
    cursor: pointer;
    font: inherit;
    font-weight: 600;
  }

  .name {
    max-width: 28ch;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .result {
    white-space: normal;
    color: var(--color-status-healthy);
  }

  .result.fail {
    color: var(--color-status-critical);
    font-weight: 600;
  }

  .result p {
    margin: 0;
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

  .link:disabled {
    cursor: progress;
    opacity: 0.7;
  }

  .danger {
    color: var(--color-status-critical);
    font-weight: 600;
  }
</style>
