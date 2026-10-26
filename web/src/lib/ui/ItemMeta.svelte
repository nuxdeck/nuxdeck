<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type ItemKind } from '../api/client';
  import { auth } from '../auth.svelte';
  import { inventory } from '../inventory.svelte';
  import { tagText, type Tags } from '../tags';
  import Button from './Button.svelte';
  import FormError from './FormError.svelte';

  interface Props {
    kind: ItemKind;
    id: string;
    owner: string;
    tags: Tags;
    etag: string;
  }

  let { kind, id, owner, tags, etag }: Props = $props();

  // Only operators and admins may change tags and owners; the server enforces it too.
  const canEdit = $derived(
    !!auth.user && (auth.user.roles.includes('operator') || auth.user.roles.includes('admin')),
  );

  interface Row {
    key: string;
    value: string;
  }

  let editing = $state(false);
  let saving = $state(false);
  let error = $state<ApiError | null>(null);
  let ownerDraft = $state('');
  let rows = $state<Row[]>([]);
  let announcement = $state('');

  const chips = $derived(tagText(tags));

  function start(): void {
    ownerDraft = owner;
    rows = Object.entries(tags)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => ({ key, value }));
    if (rows.length === 0) rows = [{ key: '', value: '' }];
    error = null;
    editing = true;
    void tick().then(() => document.getElementById('tag-key-0')?.focus());
  }

  function cancel(): void {
    editing = false;
    error = null;
  }

  function addRow(): void {
    rows = [...rows, { key: '', value: '' }];
  }

  function removeRow(i: number): void {
    rows = rows.filter((_, n) => n !== i);
    announcement = 'Tag removed';
  }

  function clientError(message: string, hint: string, field: string): ApiError {
    return { status: 422, code: 'API-VAL-001', message, hint, field };
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const next: Tags = {};
    for (const r of rows) {
      const key = r.key.trim();
      const value = r.value.trim();
      if (!key && !value) continue;
      if (!key || !value) {
        error = clientError(
          'Every tag needs a key and a value.',
          'Fill in both fields or remove the row.',
          'tags',
        );
        return;
      }
      if (key in next) {
        error = clientError('A tag key appears twice.', `Use "${key}" only once.`, 'tags');
        return;
      }
      next[key] = value;
    }

    saving = true;
    error = null;
    try {
      let current = etag;
      const tagsChanged = JSON.stringify(tagText(next)) !== JSON.stringify(tagText(tags));
      if (tagsChanged) {
        const updated = await api.putTags(kind, id, next, current);
        remember(updated);
        current = updated.etag;
      }
      if (ownerDraft.trim() !== owner) {
        remember(await api.putOwner(kind, id, ownerDraft.trim(), current));
      }
      editing = false;
      announcement = 'Tags and owner saved';
    } catch (e) {
      if (e instanceof ApiRequestError) {
        error = e.error;
        if (e.error.status === 412) await refresh();
      } else {
        throw e;
      }
    } finally {
      saving = false;
    }
  }

  function remember(item: Awaited<ReturnType<typeof api.putTags>>): void {
    if ('hostname' in item) inventory.replaceHost(item);
    else inventory.replaceContainer(item);
  }

  // After a conflict the reader sees what the other person saved, and can apply the change again.
  async function refresh(): Promise<void> {
    try {
      remember(kind === 'hosts' ? await api.host(id) : await api.container(id));
      editing = false;
      announcement = 'The item changed while you were editing. Showing the latest version.';
    } catch {
      /* the original error stays on screen */
    }
  }
</script>

<div class="meta">
  {#if !editing}
    <div class="summary">
      <span class="label">Tags</span>
      {#if chips.length === 0}
        <span class="muted">none</span>
      {:else}
        <ul class="chips" aria-label="Tags">
          {#each chips as chip (chip)}<li class="mono">{chip}</li>{/each}
        </ul>
      {/if}
      <span class="label">Owner</span>
      <span class:muted={!owner}>{owner || 'not set'}</span>
      {#if canEdit}
        <button type="button" class="link" onclick={start}>Edit tags and owner</button>
      {/if}
    </div>
  {:else}
    <form onsubmit={save} aria-label="Edit tags and owner">
      {#if error}<FormError {error} />{/if}
      <fieldset>
        <legend>Tags</legend>
        {#each rows as row, i (i)}
          <div class="row">
            <label class="visually-hidden" for="tag-key-{i}">Tag key {i + 1}</label>
            <input
              id="tag-key-{i}"
              bind:value={row.key}
              placeholder="env"
              autocomplete="off"
              spellcheck="false"
              maxlength="63"
            />
            <span aria-hidden="true">:</span>
            <label class="visually-hidden" for="tag-value-{i}">Tag value {i + 1}</label>
            <input
              id="tag-value-{i}"
              bind:value={row.value}
              placeholder="production"
              autocomplete="off"
              spellcheck="false"
              maxlength="64"
            />
            <button
              type="button"
              class="link"
              aria-label="Remove tag {row.key || i + 1}"
              onclick={() => removeRow(i)}>Remove</button
            >
          </div>
        {/each}
        <button type="button" class="link" onclick={addRow}>Add a tag</button>
      </fieldset>
      <div class="owner">
        <label for="item-owner">Owner</label>
        <input
          id="item-owner"
          bind:value={ownerDraft}
          placeholder="A team or person"
          autocomplete="off"
          maxlength="128"
        />
      </div>
      <div class="actions">
        <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save'}</Button>
        <Button variant="secondary" disabled={saving} onclick={cancel}>Cancel</Button>
      </div>
    </form>
  {/if}
  <p class="visually-hidden" role="status">{announcement}</p>
</div>

<style>
  .meta {
    margin-top: var(--space-1);
    font-size: var(--font-size-sm);
  }

  .summary {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2);
  }

  .label {
    font-weight: 600;
  }

  .muted {
    color: var(--color-text-muted);
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .chips li {
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
  }

  form {
    display: grid;
    gap: var(--space-3);
    max-width: 40rem;
  }

  fieldset {
    display: grid;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    border: 0;
  }

  legend,
  .owner label {
    font-weight: 600;
  }

  .row {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  input {
    min-height: var(--target-size);
    min-width: 0;
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  .owner {
    display: grid;
    gap: var(--space-1);
  }

  .actions {
    display: flex;
    gap: var(--space-2);
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
    justify-self: start;
  }
</style>
