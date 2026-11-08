<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script module lang="ts">
  import type { RoleScope } from '../lib/api/client';

  function split(text: string, sep: RegExp): string[] {
    return text
      .split(sep)
      .map((v) => v.trim())
      .filter(Boolean);
  }

  /** Environments are comma-separated; tag sets are one per line, tags comma-separated. */
  export function parseScope(envText: string, setText: string): RoleScope {
    const scope: RoleScope = {};
    const envs = split(envText, /,/);
    if (envs.length) scope.environments = envs;
    const sets = split(setText, /\n/)
      .map((line) => split(line, /,/))
      .filter((set) => set.length);
    if (sets.length) scope.tag_sets = sets;
    return scope;
  }

  export function describeScope(s: RoleScope): string {
    const parts: string[] = [];
    if (s.environments?.length) parts.push(`env: ${s.environments.join(', ')}`);
    for (const set of s.tag_sets ?? []) parts.push(`tags: ${set.join(' + ')}`);
    return parts.length ? parts.join('; ') : 'Everything';
  }
</script>

<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    ApiRequestError,
    type ApiError,
    type Role,
    type RoleBinding,
  } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import Button from '../lib/ui/Button.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import SelectField from '../lib/ui/SelectField.svelte';
  import TextField from '../lib/ui/TextField.svelte';

  const isAdmin = $derived(auth.user?.roles.includes('admin') ?? false);

  let items = $state<RoleBinding[]>([]);
  let loading = $state(true);
  let busy = $state(false);
  let error = $state<ApiError | null>(null);

  let subjectType = $state<string>('oidc_group');
  let subject = $state('');
  let role = $state<string>('viewer');
  let environments = $state('');
  let tagSets = $state('');
  let fieldErrors = $state<Record<string, string>>({});

  const subjectTypes = [
    { value: 'oidc_group', label: 'SSO group' },
    { value: 'user', label: 'User ID' },
  ];
  const roles = [
    { value: 'viewer', label: 'Viewer (read-only)' },
    { value: 'operator', label: 'Operator (checks, alerts, silences)' },
    { value: 'admin', label: 'Admin (everything)' },
  ];

  async function load() {
    try {
      items = await api.roleBindings();
      error = null;
    } catch (e) {
      if (e instanceof ApiRequestError) error = e.error;
    } finally {
      loading = false;
    }
  }

  async function add() {
    fieldErrors = {};
    if (!subject.trim()) {
      fieldErrors = { subject: 'Enter a user ID or group name.' };
      return;
    }
    busy = true;
    try {
      await api.createRoleBinding({
        subject_type: subjectType as 'user' | 'oidc_group',
        subject: subject.trim(),
        role: role as Role,
        scope: parseScope(environments, tagSets),
      });
      subject = '';
      environments = '';
      tagSets = '';
      error = null;
      await load();
    } catch (e) {
      if (e instanceof ApiRequestError) {
        error = e.error;
        if (e.error.field) fieldErrors = { [e.error.field]: e.error.hint };
      }
    } finally {
      busy = false;
    }
  }

  async function remove(b: RoleBinding) {
    busy = true;
    try {
      await api.deleteRoleBinding(b.id);
      error = null;
      await load();
    } catch (e) {
      if (e instanceof ApiRequestError) error = e.error;
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    if (isAdmin) void load();
  });
</script>

{#if !isAdmin}
  <p>Only administrators can manage roles.</p>
{:else}
  <section aria-labelledby="rb-heading">
    <h2 id="rb-heading">Role bindings</h2>
    <p>
      A role can apply everywhere or only to part of the inventory. A scoped role covers items in
      the listed environments, or items that carry every tag of one tag set. Items without an
      environment or tags, and settings such as checks and channels, need a role that applies
      everywhere.
    </p>
    {#if error}<FormError {error} />{/if}

    {#if loading}
      <p>Loading role bindings.</p>
    {:else if items.length === 0}
      <p>No role bindings yet.</p>
    {:else}
      <table>
        <caption class="sr-only">Role bindings</caption>
        <thead>
          <tr
            ><th scope="col">Who</th><th scope="col">Role</th><th scope="col">Scope</th><th
              scope="col"><span class="sr-only">Actions</span></th
            ></tr
          >
        </thead>
        <tbody>
          {#each items as b (b.id)}
            <tr>
              <td>{b.subject_type === 'user' ? 'User' : 'Group'} <code>{b.subject}</code></td>
              <td>{b.role}</td>
              <td>
                {describeScope(b.scope)}
                {#if b.invalid}<strong> (unreadable scope: grants nothing)</strong>{/if}
              </td>
              <td>
                <Button variant="secondary" disabled={busy} onclick={() => remove(b)}>
                  Remove<span class="sr-only"> {b.role} for {b.subject}</span>
                </Button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    <h3 id="rb-add">Add a role binding</h3>
    <form
      aria-labelledby="rb-add"
      onsubmit={(e) => {
        e.preventDefault();
        void add();
      }}
    >
      <SelectField
        id="rb-type"
        label="Applies to"
        bind:value={subjectType}
        options={subjectTypes}
      />
      <TextField
        id="rb-subject"
        label={subjectType === 'user' ? 'User ID' : 'Group name'}
        bind:value={subject}
        error={fieldErrors.subject}
        required
        maxlength={256}
      />
      <SelectField
        id="rb-role"
        label="Role"
        bind:value={role}
        options={roles}
        error={fieldErrors.role}
      />
      <TextField
        id="rb-env"
        label="Environments"
        bind:value={environments}
        hint="Comma-separated, for example staging, qa. Leave empty to apply everywhere."
        error={fieldErrors.scope}
      />
      <label for="rb-tags">Tag sets</label>
      <textarea id="rb-tags" rows="3" bind:value={tagSets} aria-describedby="rb-tags-hint"
      ></textarea>
      <p id="rb-tags-hint" class="hint">
        One set per line, tags comma-separated, for example team:web, tier:1. A line matches items
        that carry every tag on it.
      </p>
      <Button type="submit" disabled={busy}>Add role binding</Button>
    </form>
  </section>
{/if}

<style>
  table {
    width: 100%;
    border-collapse: collapse;
  }

  th,
  td {
    text-align: left;
    padding: var(--space-2);
    border-bottom: 1px solid var(--color-border);
  }

  form {
    display: grid;
    gap: var(--space-3);
    max-width: 48ch;
  }

  .hint {
    color: var(--color-text-muted);
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
  }
</style>
