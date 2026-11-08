<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type StatusPage } from '../lib/api/client';
  import { findSection } from '../lib/router.svelte';
  import { canWriteStatusPages, publicUrl } from '../lib/statuspages/form';
  import PageEditor from '../lib/statuspages/PageEditor.svelte';
  import Button from '../lib/ui/Button.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';

  const section = findSection('/status-pages');
  const canWrite = $derived(canWriteStatusPages());

  let items = $state<StatusPage[]>([]);
  let loaded = $state(false);
  let failure = $state<ApiError | null>(null);
  // undefined: showing the list; null: creating; a string: editing that page.
  let editing = $state<string | null | undefined>(undefined);
  let copied = $state('');

  async function load(): Promise<void> {
    try {
      items = await api.statusPages();
      failure = null;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
    } finally {
      loaded = true;
    }
  }

  onMount(() => void load());

  async function closeEditor(): Promise<void> {
    editing = undefined;
    await load();
    await tick();
    document.getElementById('page-title')?.focus();
  }

  async function copy(p: StatusPage): Promise<void> {
    try {
      await navigator.clipboard.writeText(publicUrl(p.slug));
      copied = `Copied the address of ${p.title}`;
    } catch {
      copied = `Copy failed. The address is ${publicUrl(p.slug)}`;
    }
  }
</script>

{#if editing !== undefined}
  <h1 id="page-title" tabindex="-1" class="visually-hidden">{section?.title}</h1>
  {#key editing}
    <PageEditor id={editing ?? undefined} onclose={() => void closeEditor()} />
  {/key}
{:else}
  <div class="head">
    <div>
      <h1 id="page-title" tabindex="-1">{section?.title}</h1>
      <p class="question">{section?.question}</p>
    </div>
    {#if canWrite}<Button onclick={() => (editing = null)}>New status page</Button>{/if}
  </div>
  <p class="visually-hidden" role="status">{copied}</p>

  {#if failure}
    <FormError error={failure} />
  {:else if !loaded}
    <p role="status">Loading…</p>
  {:else if items.length === 0}
    <EmptyState title="No status pages yet">
      Public status pages you publish appear here.
      {#if canWrite}Create one to share the health of your services.{:else}An operator can create
        one.{/if}
    </EmptyState>
  {:else}
    <div class="table-wrap">
      <table class="data-table">
        <caption class="visually-hidden">Status pages</caption>
        <thead>
          <tr>
            <th scope="col">Title</th>
            <th scope="col">State</th>
            <th scope="col">Public address</th>
            <th scope="col"><span class="visually-hidden">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each items as p (p.id)}
            <tr>
              <th scope="row">{p.title}</th>
              <td
                ><span class="state" class:live={p.published}
                  >{p.published ? 'Published' : 'Draft'}</span
                ></td
              >
              <td class="mono">/status/{p.slug}</td>
              <td class="actions">
                <Button variant="secondary" onclick={() => (editing = p.id)}
                  >{canWrite ? 'Edit ' : 'View '}<span class="visually-hidden">{p.title}</span
                  ></Button
                >
                <Button variant="secondary" onclick={() => void copy(p)}
                  >Copy link <span class="visually-hidden">for {p.title}</span></Button
                >
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-3);
  }

  .question {
    margin: var(--space-1) 0 var(--space-6);
    color: var(--color-text-muted);
  }

  .state {
    padding: 0 var(--space-2);
    border-radius: var(--radius-1);
    background: var(--color-status-unknown-bg);
    color: var(--color-status-unknown);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .state.live {
    background: var(--color-status-healthy-bg);
    color: var(--color-status-healthy);
  }

  .actions {
    display: flex;
    gap: var(--space-2);
    justify-content: flex-end;
  }
</style>
