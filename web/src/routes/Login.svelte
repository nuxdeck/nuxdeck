<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { ApiRequestError, type ApiError, type TotpEnrolment } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import AuthCard from '../lib/ui/AuthCard.svelte';
  import Button from '../lib/ui/Button.svelte';
  import Field from '../lib/ui/Field.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import RecoveryCodes from '../lib/ui/RecoveryCodes.svelte';
  import SsoLoginButton from '../lib/ui/SsoLoginButton.svelte';
  import TotpSetup from '../lib/ui/TotpSetup.svelte';

  let email = $state('');
  let password = $state('');
  let code = $state('');
  let busy = $state(false);
  let failure = $state<ApiError | null>(null);
  let enrolment = $state<TotpEnrolment | null>(null);

  function fail(e: unknown): void {
    failure = e instanceof ApiRequestError ? e.error : null;
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    failure = null;
    try {
      await auth.login(email, password);
      if (auth.pending?.enrol_required) enrolment = await auth.pendingEnrol();
    } catch (e) {
      fail(e);
    } finally {
      password = '';
      busy = false;
    }
  }

  async function verify(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    failure = null;
    try {
      await auth.verifyTotp(code);
    } catch (e) {
      fail(e);
      code = '';
      // A burnt or expired ticket cannot be retried: start over with the password.
      if (e instanceof ApiRequestError && e.error.code === 'AUTH-TOTP-002') back();
    } finally {
      busy = false;
    }
  }

  function back(): void {
    auth.cancelPending();
    enrolment = null;
    code = '';
  }
</script>

{#if auth.recoveryCodes}
  <AuthCard title="Save your recovery codes">
    <RecoveryCodes codes={auth.recoveryCodes} onDone={() => auth.finishRecovery()} />
  </AuthCard>
{:else if auth.pending}
  <AuthCard title="Two-factor authentication">
    <form onsubmit={verify}>
      {#if failure}<FormError error={failure} />{/if}
      {#if enrolment}
        <p>
          Your administrator requires two-factor authentication. Add Nux Deck to your authenticator
          app first.
        </p>
        <TotpSetup {enrolment} />
      {:else}
        <p>Enter the 6-digit code from your authenticator app, or a recovery code.</p>
      {/if}
      <Field
        id="totp-code"
        label="Code"
        bind:value={code}
        autocomplete="one-time-code"
        disabled={busy}
      />
      <Button type="submit" disabled={busy}>{busy ? 'Checking…' : 'Verify'}</Button>
      <Button variant="secondary" onclick={back} disabled={busy}>Back to sign in</Button>
    </form>
  </AuthCard>
{:else}
  <AuthCard title="Sign in to Nux Deck">
    <form onsubmit={submit}>
      {#if failure}<FormError error={failure} />{/if}
      <Field
        id="email"
        label="Email"
        type="email"
        bind:value={email}
        autocomplete="username"
        disabled={busy}
      />
      <Field
        id="password"
        label="Password"
        type="password"
        bind:value={password}
        autocomplete="current-password"
        disabled={busy}
      />
      <Button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
    </form>
    <SsoLoginButton />
  </AuthCard>
{/if}

<style>
  form {
    display: grid;
    gap: var(--space-4);
  }
</style>
