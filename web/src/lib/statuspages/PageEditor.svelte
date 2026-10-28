<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type Check, type StatusPage } from '../api/client';
  import Button from '../ui/Button.svelte';
  import FormError from '../ui/FormError.svelte';
  import TextAreaField from '../ui/TextAreaField.svelte';
  import TextField from '../ui/TextField.svelte';
  import ToggleField from '../ui/ToggleField.svelte';
  import IncidentPanel from './IncidentPanel.svelte';
  import PublicPreview from './PublicPreview.svelte';
  import {
    MAX_COMPONENT_NAME,
    MAX_COMPONENTS,
    MAX_DESCRIPTION,
    MAX_TITLE,
    canWriteStatusPages,
    emptyForm,
    formFromPage,
    move,
    newComponent,
    publicUrl,
    toInput,
    validate,
    type PageErrors,
    type PageForm,
  } from './form';

  interface Props {
    /** The page being edited; absent when creating. */
    id?: string;
    onclose: () => void;
  }

  let { id, onclose }: Props = $props();

  // `id` only seeds the editor; after a create, `pageId` takes over.
  // svelte-ignore state_referenced_locally
  let pageId = $state<string | undefined>(id);
  const editing = $derived(pageId !== undefined);
  const canWrite = $derived(canWriteStatusPages());

  let form = $state<PageForm>(emptyForm());
  let etag = $state('');
  let checks = $state<Check[]>([]);
  let loading = $state(false);
  let loadError = $state<ApiError | null>(null);
  let missing = $state(false);
  let saving = $state(false);
  let errors = $state<PageErrors>({});
  let failure = $state<ApiError | null>(null);
  let announce = $state('');
  let version = $state('');
  let confirmDelete = $state(false);

  const url = $derived(form.slug ? publicUrl(form.slug) : '');

  function adopt(p: StatusPage, tag: string): void {
    form = formFromPage(p);
    etag = tag;
    version = `${tag}:${p.updated_at}`;
  }

  async function load(): Promise<void> {
    loading = true;
    loadError = null;
    try {
      const [list, loaded] = await Promise.all([
        api.checks(),
        pageId ? api.statusPage(pageId) : Promise.resolve(null),
      ]);
      checks = list;
      if (loaded) adopt(loaded.page, loaded.etag);
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      if (e.error.status === 404) missing = true;
      else loadError = e.error;
    } finally {
      loading = false;
    }
  }

  onMount(() => void load());

  function checkLabel(checkId: string): string {
    const c = checks.find((x) => x.id === checkId);
    return c ? `${c.name} (${c.type})` : 'A check that no longer exists';
  }

  /** Checks to offer for a component: all existing ones, plus any it still names that were deleted. */
  function optionsFor(selected: string[]): string[] {
    const known = checks.map((c) => c.id);
    return [...known, ...selected.filter((s) => !known.includes(s))];
  }

  function toggleCheck(index: number, checkId: string, on: boolean): void {
    const c = form.components[index];
    if (!c) return;
    c.check_ids = on ? [...c.check_ids, checkId] : c.check_ids.filter((x) => x !== checkId);
  }

  function addComponent(): void {
    form.components = [...form.components, newComponent()];
    const key = form.components.at(-1)?.key;
    void tick().then(() => document.getElementById(`sp-c${key}-name`)?.focus());
  }

  async function relocate(index: number, to: number): Promise<void> {
    const c = form.components[index];
    if (!c) return;
    form.components = move(form.components, index, to);
    announce = `${c.name || 'Component'} moved to position ${to + 1} of ${form.components.length}`;
    await tick();
    const target = document.getElementById(`sp-c${c.key}-${to > index ? 'down' : 'up'}`);
    const fallback = document.getElementById(`sp-c${c.key}-${to > index ? 'up' : 'down'}`);
    (target && !(target as HTMLButtonElement).disabled ? target : fallback)?.focus();
  }

  async function removeComponent(index: number): Promise<void> {
    const c = form.components[index];
    if (!c) return;
    form.components = form.components.filter((_, i) => i !== index);
    announce = `${c.name || 'Component'} removed`;
    await tick();
    const next = form.components[Math.min(index, form.components.length - 1)];
    (next
      ? document.getElementById(`sp-c${next.key}-name`)
      : document.getElementById('sp-add')
    )?.focus();
  }

  const FIELD_IDS: Record<string, string> = {
    slug: 'sp-slug',
    title: 'sp-title',
    description: 'sp-description',
    components: 'sp-add',
  };

  function focusFirst(found: PageErrors): void {
    const order = ['slug', 'title', 'description', 'components'];
    for (const key of order) {
      if (found[key]) return void document.getElementById(FIELD_IDS[key]!)?.focus();
    }
    const first = form.components.findIndex((_, i) => found[`components[${i}].name`]);
    if (first >= 0) document.getElementById(`sp-c${form.components[first]!.key}-name`)?.focus();
  }

  /** Server messages name a field such as components[1].check_ids; show them beside it when we can. */
  function adoptServerError(e: ApiError): void {
    const field = e.field;
    if (field && (field in FIELD_IDS || /^components\[\d+\]\.(name|check_ids)$/.test(field))) {
      errors = { ...errors, [field]: e.hint };
      return;
    }
    failure = e;
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    failure = null;
    announce = '';
    const found = validate(form, !editing);
    errors = found;
    if (Object.keys(found).length > 0) {
      await tick();
      focusFirst(found);
      return;
    }
    saving = true;
    try {
      const saved =
        pageId !== undefined
          ? await api.updateStatusPage(pageId, toInput(form), etag)
          : await api.createStatusPage(toInput(form));
      pageId = saved.page.id;
      adopt(saved.page, saved.etag);
      announce = 'Status page saved';
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      adoptServerError(e.error);
      await tick();
      if (!failure) {
        document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
      }
    } finally {
      saving = false;
    }
  }

  async function remove(): Promise<void> {
    if (pageId === undefined) return;
    failure = null;
    saving = true;
    try {
      await api.deleteStatusPage(pageId);
      onclose();
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
      confirmDelete = false;
    } finally {
      saving = false;
    }
  }
</script>

<div class="editor">
  <div class="head">
    <h2 id="editor-title" tabindex="-1">
      {editing ? `Edit ${form.title || 'status page'}` : 'New status page'}
    </h2>
    <Button variant="secondary" onclick={onclose}>Back to status pages</Button>
  </div>

  {#if loading}
    <p role="status">Loading…</p>
  {:else if missing}
    <p role="alert">This status page no longer exists.</p>
  {:else if loadError}
    <FormError error={loadError} />
  {:else}
    <p class="visually-hidden" role="status">{announce}</p>
    {#if !canWrite}
      <p class="note" role="status">
        You can view this page. Only operators and admins can change it.
      </p>
    {/if}

    <form onsubmit={save} novalidate aria-labelledby="editor-title">
      {#if failure}
        <FormError error={failure} />
        {#if failure.status === 412}
          <div>
            <Button variant="secondary" onclick={() => void load()}>Reload latest version</Button>
          </div>
        {/if}
      {/if}

      <TextField
        id="sp-slug"
        label="Address (slug)"
        bind:value={form.slug}
        error={errors.slug}
        hint={editing
          ? 'The slug cannot be changed after the page is created.'
          : 'Lowercase letters, digits and hyphens. It becomes part of the public address.'}
        disabled={editing || !canWrite}
        required
        mono
        maxlength={64}
      />
      {#if url}<p class="url">Public address: <span class="mono">{url}</span></p>{/if}
      <TextField
        id="sp-title"
        label="Title"
        bind:value={form.title}
        error={errors.title}
        maxlength={MAX_TITLE}
        disabled={!canWrite}
        required
      />
      <TextAreaField
        id="sp-description"
        label="Description"
        bind:value={form.description}
        error={errors.description}
        maxlength={MAX_DESCRIPTION}
        rows={3}
        disabled={!canWrite}
      />
      <ToggleField
        id="sp-published"
        label="Published"
        bind:checked={form.published}
        hint="Anyone with the address can read a published page, without signing in. Unpublished pages return not found."
        disabled={!canWrite}
      />

      <fieldset class="components">
        <legend>Components</legend>
        <p class="hint">
          A component groups checks. Its status is operational when all of its checks are up,
          degraded when some are down, and an outage when all are down. Visitors see component names
          only, never check names or targets.
        </p>
        {#if errors.components}<p class="error" id="sp-components-error">
            {errors.components}
          </p>{/if}
        {#each form.components as c, i (c.key)}
          {@const n = i + 1}
          <div class="component" role="group" aria-label="Component {n}">
            <TextField
              id="sp-c{c.key}-name"
              label="Component {n} name"
              bind:value={c.name}
              error={errors[`components[${i}].name`]}
              maxlength={MAX_COMPONENT_NAME}
              disabled={!canWrite}
              required
            />
            <fieldset class="checks">
              <legend>Checks for component {n}</legend>
              {#if checks.length === 0 && c.check_ids.length === 0}
                <p class="hint">There are no checks yet. Add checks first, then pick them here.</p>
              {/if}
              {#each optionsFor(c.check_ids) as checkId (checkId)}
                <div class="check">
                  <input
                    id="sp-c{c.key}-check-{checkId}"
                    type="checkbox"
                    checked={c.check_ids.includes(checkId)}
                    disabled={!canWrite}
                    onchange={(e) => toggleCheck(i, checkId, e.currentTarget.checked)}
                  />
                  <label for="sp-c{c.key}-check-{checkId}">{checkLabel(checkId)}</label>
                </div>
              {/each}
              {#if errors[`components[${i}].check_ids`]}
                <p class="error">{errors[`components[${i}].check_ids`]}</p>
              {/if}
            </fieldset>
            {#if canWrite}
              <div class="row-actions">
                <button
                  type="button"
                  id="sp-c{c.key}-up"
                  aria-label="Move {c.name || `component ${n}`} up"
                  disabled={i === 0}
                  onclick={() => void relocate(i, i - 1)}>Move up</button
                >
                <button
                  type="button"
                  id="sp-c{c.key}-down"
                  aria-label="Move {c.name || `component ${n}`} down"
                  disabled={i === form.components.length - 1}
                  onclick={() => void relocate(i, i + 1)}>Move down</button
                >
                <button
                  type="button"
                  id="sp-c{c.key}-remove"
                  aria-label="Remove {c.name || `component ${n}`}"
                  onclick={() => void removeComponent(i)}>Remove</button
                >
              </div>
            {/if}
          </div>
        {/each}
        {#if canWrite}
          <div>
            <button
              type="button"
              id="sp-add"
              class="add"
              disabled={form.components.length >= MAX_COMPONENTS}
              onclick={addComponent}>Add component</button
            >
          </div>
        {/if}
      </fieldset>

      {#if canWrite}
        <div class="actions">
          <Button type="submit" disabled={saving}
            >{editing ? 'Save changes' : 'Create status page'}</Button
          >
          {#if editing}
            <Button variant="secondary" disabled={saving} onclick={() => (confirmDelete = true)}
              >Delete page</Button
            >
          {/if}
        </div>
      {/if}
    </form>

    {#if confirmDelete}
      <div
        class="confirm"
        role="alertdialog"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-text"
      >
        <p id="confirm-title"><strong>Delete this status page?</strong></p>
        <p id="confirm-text">
          The public address stops working, and its incidents are deleted. This cannot be undone.
        </p>
        <div class="actions">
          <Button disabled={saving} onclick={() => void remove()}>Delete status page</Button>
          <Button variant="secondary" onclick={() => (confirmDelete = false)}>Cancel</Button>
        </div>
      </div>
    {/if}

    {#if editing && pageId}
      <IncidentPanel {pageId} onchange={() => (version = `${version}+`)} />
      <PublicPreview slug={form.slug} published={form.published} {version} />
    {/if}
  {/if}
</div>

<style>
  .editor,
  form {
    display: grid;
    gap: var(--space-4);
  }

  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
  }

  h2 {
    font-size: var(--font-size-lg);
  }

  h2:focus {
    outline: none;
  }

  .note,
  .hint,
  .url {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .error {
    margin: 0;
    color: var(--color-status-critical);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  fieldset {
    min-width: 0;
    margin: 0;
    padding: var(--space-4);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
  }

  .components {
    display: grid;
    gap: var(--space-3);
  }

  legend {
    padding: 0 var(--space-2);
    font-weight: 700;
  }

  .component {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
    background: var(--color-surface);
  }

  .checks {
    display: grid;
    gap: var(--space-2);
  }

  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-height: var(--target-size);
  }

  .row-actions,
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .row-actions button,
  .add {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font-weight: 600;
    cursor: pointer;
  }

  .row-actions button:disabled,
  .add:disabled {
    cursor: not-allowed;
    opacity: 0.6;
  }

  .confirm {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-4);
    border: 1px solid var(--color-status-critical);
    border-radius: var(--radius-2);
    background: var(--color-status-critical-bg);
    color: var(--color-status-critical);
  }

  .confirm p {
    margin: 0;
  }
</style>
