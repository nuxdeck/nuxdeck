<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiRequestError, type Account, type ApiError } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import Button from '../lib/ui/Button.svelte';
  import Field from '../lib/ui/Field.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import SelectField from '../lib/ui/SelectField.svelte';
  import ToggleField from '../lib/ui/ToggleField.svelte';

  const ROLE_OPTIONS = [
    { value: 'viewer', label: 'viewer' },
    { value: 'operator', label: 'operator' },
    { value: 'admin', label: 'admin' },
  ];

  let users = $state<Account[]>([]);
  let require2fa = $state(false);
  let failure = $state<ApiError | null>(null);

  let email = $state('');
  let name = $state('');
  let password = $state('');
  let role = $state('viewer');
  let createFailure = $state<ApiError | null>(null);

  let resetting = $state<Account | null>(null);
  let resetPassword = $state('');
  let resetFailure = $state<ApiError | null>(null);

  function errOf(e: unknown): ApiError | null {
    return e instanceof ApiRequestError ? e.error : null;
  }

  async function load(): Promise<void> {
    try {
      const [list, sec] = await Promise.all([api.users(), api.securitySettings()]);
      users = list;
      require2fa = sec.require_2fa;
    } catch (e) {
      failure = errOf(e);
    }
  }

  onMount(() => void load());

  async function run(action: () => Promise<unknown>): Promise<void> {
    failure = null;
    try {
      await action();
      await load();
    } catch (e) {
      failure = errOf(e);
      await load();
    }
  }

  async function create(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    createFailure = null;
    try {
      await api.createUser({ email, name, password, role });
      email = name = password = '';
      await load();
    } catch (e) {
      createFailure = errOf(e);
    }
  }

  async function reset(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (!resetting) return;
    resetFailure = null;
    try {
      await api.resetUser(resetting.id, resetPassword);
      resetting = null;
      await load();
    } catch (e) {
      resetFailure = errOf(e);
    } finally {
      resetPassword = '';
    }
  }

  function remove(u: Account): void {
    if (window.confirm(`Delete ${u.email}? This cannot be undone.`)) {
      void run(() => api.deleteUser(u.id));
    }
  }
</script>

<h1 id="page-title" tabindex="-1">Users</h1>
<p class="question">Who can sign in, and what can they do?</p>

{#if failure}<FormError error={failure} />{/if}

<section aria-labelledby="policy-h">
  <h2 id="policy-h">Sign-in policy</h2>
  <ToggleField
    id="require-2fa"
    label="Require two-factor authentication for everyone"
    hint="Users without an authenticator are asked to set one up at their next sign-in."
    bind:checked={require2fa}
    onchange={() => void run(() => api.setRequire2fa(require2fa))}
  />
</section>

<section aria-labelledby="list-h">
  <h2 id="list-h">Accounts</h2>
  <table>
    <thead>
      <tr
        ><th>Name</th><th>Email</th><th>Role</th><th>Two-factor</th><th>Status</th><th
          ><span class="sr-only">Actions</span></th
        ></tr
      >
    </thead>
    <tbody>
      {#each users as u (u.id)}
        <tr>
          <td
            >{u.name}{#if u.id === auth.user?.id}
              <em>(you)</em>{/if}</td
          >
          <td>{u.email}</td>
          <td>
            <select
              aria-label={`Role of ${u.email}`}
              value={u.role}
              onchange={(e) =>
                void run(() => api.updateUser(u.id, { role: e.currentTarget.value }))}
            >
              {#each ROLE_OPTIONS as o (o.value)}<option value={o.value}>{o.label}</option>{/each}
            </select>
          </td>
          <td>{u.totp_enabled ? 'on' : 'off'}</td>
          <td>{u.disabled ? 'disabled' : 'active'}</td>
          <td class="actions">
            <Button
              variant="secondary"
              onclick={() => void run(() => api.updateUser(u.id, { disabled: !u.disabled }))}
            >
              {u.disabled ? 'Enable' : 'Disable'}
            </Button>
            <Button variant="secondary" onclick={() => ((resetting = u), (resetFailure = null))}
              >Reset</Button
            >
            <Button variant="secondary" onclick={() => remove(u)}>Delete</Button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

{#if resetting}
  <section aria-labelledby="reset-h">
    <h2 id="reset-h">Reset {resetting.email}</h2>
    <p>Sets a new password, removes their two-factor and signs them out everywhere.</p>
    <form onsubmit={reset}>
      {#if resetFailure}<FormError error={resetFailure} />{/if}
      <Field
        id="reset-pw"
        label="Temporary password"
        type="password"
        bind:value={resetPassword}
        autocomplete="new-password"
      />
      <Button type="submit">Reset account</Button>
      <Button variant="secondary" onclick={() => (resetting = null)}>Cancel</Button>
    </form>
  </section>
{/if}

<section aria-labelledby="add-h">
  <h2 id="add-h">Add a user</h2>
  <form onsubmit={create}>
    {#if createFailure}<FormError error={createFailure} />{/if}
    <Field id="new-email" label="Email" type="email" bind:value={email} autocomplete="off" />
    <Field id="new-name" label="Name" bind:value={name} autocomplete="off" />
    <Field
      id="new-pw"
      label="Initial password"
      type="password"
      bind:value={password}
      autocomplete="new-password"
      hint="At least 12 characters. Share it securely."
    />
    <SelectField id="new-role" label="Role" bind:value={role} options={ROLE_OPTIONS} />
    <Button type="submit">Add user</Button>
  </form>
</section>

<style>
  section {
    display: grid;
    gap: var(--space-3);
    max-width: 56rem;
    margin-top: var(--space-6);
  }

  form {
    display: grid;
    gap: var(--space-3);
    max-width: 28rem;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th,
  td {
    text-align: left;
    padding: var(--space-2);
    border-bottom: 1px solid var(--color-border);
    vertical-align: middle;
  }

  .actions {
    display: flex;
    gap: var(--space-2);
    flex-wrap: wrap;
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
