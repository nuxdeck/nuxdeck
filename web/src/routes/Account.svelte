<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    ApiRequestError,
    type ApiError,
    type ApiToken,
    type SecurityStatus,
    type SessionInfo,
    type TotpEnrolment,
  } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import { formatTime } from '../lib/format';
  import Button from '../lib/ui/Button.svelte';
  import Field from '../lib/ui/Field.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import RecoveryCodes from '../lib/ui/RecoveryCodes.svelte';
  import SelectField from '../lib/ui/SelectField.svelte';
  import TotpSetup from '../lib/ui/TotpSetup.svelte';

  const ROLES = ['viewer', 'operator', 'admin'] as const;

  let security = $state<SecurityStatus | null>(null);
  let sessions = $state<SessionInfo[]>([]);
  let tokens = $state<ApiToken[]>([]);
  let loadFailure = $state<ApiError | null>(null);

  let current = $state('');
  let next = $state('');
  let pwFailure = $state<ApiError | null>(null);
  let pwDone = $state(false);

  let enrolment = $state<TotpEnrolment | null>(null);
  let confirmCode = $state('');
  let recovery = $state<string[] | null>(null);
  let totpFailure = $state<ApiError | null>(null);
  let disablePassword = $state('');

  let tokenName = $state('');
  let tokenRole = $state('viewer');
  let tokenDays = $state('30');
  let tokenFailure = $state<ApiError | null>(null);
  let newToken = $state<string | null>(null);

  const myRole = $derived(ROLES.filter((r) => auth.user?.roles.includes(r)).at(-1) ?? 'viewer');
  const roleOptions = $derived(
    ROLES.slice(0, ROLES.indexOf(myRole) + 1).map((r) => ({ value: r, label: r })),
  );

  function errOf(e: unknown): ApiError | null {
    return e instanceof ApiRequestError ? e.error : null;
  }

  async function load(): Promise<void> {
    try {
      [security, sessions, tokens] = await Promise.all([
        api.mySecurity(),
        api.mySessions(),
        api.myTokens(),
      ]);
      loadFailure = null;
    } catch (e) {
      loadFailure = errOf(e);
    }
  }

  onMount(() => void load());

  async function changePassword(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    pwFailure = null;
    pwDone = false;
    try {
      await api.changePassword(current, next);
      pwDone = true;
      await load();
    } catch (e) {
      pwFailure = errOf(e);
    } finally {
      current = '';
      next = '';
    }
  }

  async function startEnrol(): Promise<void> {
    totpFailure = null;
    try {
      enrolment = await api.totpEnrol();
    } catch (e) {
      totpFailure = errOf(e);
    }
  }

  async function confirm(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    totpFailure = null;
    try {
      recovery = (await api.totpConfirm(confirmCode)).recovery_codes;
      enrolment = null;
      await load();
    } catch (e) {
      totpFailure = errOf(e);
    } finally {
      confirmCode = '';
    }
  }

  async function disable(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    totpFailure = null;
    try {
      await api.totpDisable(disablePassword);
      await load();
    } catch (e) {
      totpFailure = errOf(e);
    } finally {
      disablePassword = '';
    }
  }

  async function revokeSession(s: SessionInfo): Promise<void> {
    try {
      await api.revokeMySession(s.id);
      if (s.current) {
        await auth.logout();
        return;
      }
      await load();
    } catch (e) {
      loadFailure = errOf(e);
    }
  }

  async function createToken(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    tokenFailure = null;
    try {
      const made = await api.createToken({
        name: tokenName,
        expires_in_days: Number(tokenDays),
        bindings: [{ role: tokenRole, scope: {} }],
      });
      newToken = made.token;
      tokenName = '';
      await load();
    } catch (e) {
      tokenFailure = errOf(e);
    }
  }

  async function revokeToken(t: ApiToken): Promise<void> {
    try {
      await api.revokeToken(t.id);
      await load();
    } catch (e) {
      loadFailure = errOf(e);
    }
  }
</script>

<h1 id="page-title" tabindex="-1">Account</h1>
<p class="question">{auth.user?.name} · {auth.user?.email}</p>

{#if loadFailure}<FormError error={loadFailure} />{/if}

<section aria-labelledby="pw-h">
  <h2 id="pw-h">Password</h2>
  <form onsubmit={changePassword}>
    {#if pwFailure}<FormError error={pwFailure} />{/if}
    {#if pwDone}<p role="status">Password changed. Your other sessions were signed out.</p>{/if}
    <Field
      id="pw-current"
      label="Current password"
      type="password"
      bind:value={current}
      autocomplete="current-password"
    />
    <Field
      id="pw-new"
      label="New password"
      type="password"
      bind:value={next}
      autocomplete="new-password"
      hint="At least 12 characters."
    />
    <Button type="submit">Change password</Button>
  </form>
</section>

<section aria-labelledby="totp-h">
  <h2 id="totp-h">Two-factor authentication</h2>
  {#if totpFailure}<FormError error={totpFailure} />{/if}
  {#if recovery}
    <RecoveryCodes codes={recovery} onDone={() => (recovery = null)} />
  {:else if security?.totp_enabled}
    <p>Two-factor is on. {security.recovery_codes_left} recovery codes left.</p>
    {#if security.require_2fa}
      <p>Your administrator requires two-factor, so it cannot be turned off.</p>
    {:else}
      <form onsubmit={disable}>
        <Field
          id="totp-off-pw"
          label="Password"
          type="password"
          bind:value={disablePassword}
          autocomplete="current-password"
        />
        <Button type="submit" variant="secondary">Turn off two-factor</Button>
      </form>
    {/if}
  {:else if enrolment}
    <TotpSetup {enrolment} />
    <form onsubmit={confirm}>
      <Field
        id="totp-confirm"
        label="Code from the app"
        bind:value={confirmCode}
        autocomplete="one-time-code"
      />
      <Button type="submit">Turn on two-factor</Button>
    </form>
  {:else if security}
    <p>Add a second step to sign-in with an authenticator app.</p>
    <Button onclick={() => void startEnrol()}>Set up two-factor</Button>
  {/if}
</section>

<section aria-labelledby="sess-h">
  <h2 id="sess-h">Sessions</h2>
  <table>
    <thead
      ><tr
        ><th>Started</th><th>Last active</th><th>Address</th><th>Browser</th><th
          ><span class="sr-only">Actions</span></th
        ></tr
      ></thead
    >
    <tbody>
      {#each sessions as s (s.id)}
        <tr>
          <td
            >{formatTime(s.created_at)}{#if s.current}
              <strong>(this session)</strong>{/if}</td
          >
          <td>{formatTime(s.last_seen_at)}</td>
          <td>{s.ip}</td>
          <td class="ua">{s.user_agent}</td>
          <td
            ><Button variant="secondary" onclick={() => void revokeSession(s)}
              >{s.current ? 'Sign out' : 'Revoke'}</Button
            ></td
          >
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<section aria-labelledby="tok-h">
  <h2 id="tok-h">API tokens</h2>
  <p>
    Tokens act as you, with at most the role you choose. Use them with <code
      >Authorization: Bearer</code
    >.
  </p>
  {#if newToken}
    <div class="new-token">
      <p role="status"><strong>Copy this token now. It is shown only once.</strong></p>
      <code>{newToken}</code>
      <Button variant="secondary" onclick={() => (newToken = null)}>I have copied it</Button>
    </div>
  {/if}
  <form onsubmit={createToken}>
    {#if tokenFailure}<FormError error={tokenFailure} />{/if}
    <Field id="tok-name" label="Name" bind:value={tokenName} />
    <SelectField id="tok-role" label="Role" bind:value={tokenRole} options={roleOptions} />
    <SelectField
      id="tok-days"
      label="Expires in"
      bind:value={tokenDays}
      options={[
        { value: '7', label: '7 days' },
        { value: '30', label: '30 days' },
        { value: '90', label: '90 days' },
        { value: '365', label: '1 year' },
      ]}
    />
    <Button type="submit">Create token</Button>
  </form>
  {#if tokens.length}
    <table>
      <thead
        ><tr
          ><th>Name</th><th>Role</th><th>Expires</th><th>Last used</th><th
            ><span class="sr-only">Actions</span></th
          ></tr
        ></thead
      >
      <tbody>
        {#each tokens as t (t.id)}
          <tr>
            <td>{t.name}</td>
            <td>{t.bindings.map((b) => b.role).join(', ')}</td>
            <td>{formatTime(t.expires_at)}</td>
            <td>{t.last_used_at ? formatTime(t.last_used_at) : 'never'}</td>
            <td><Button variant="secondary" onclick={() => void revokeToken(t)}>Revoke</Button></td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<style>
  section {
    display: grid;
    gap: var(--space-3);
    max-width: 48rem;
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

  .ua {
    max-width: 18ch;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .new-token {
    display: grid;
    gap: var(--space-2);
    padding: var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
  }

  .new-token code {
    overflow-wrap: anywhere;
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
