<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { ApiRequestError, type ApiError } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import AuthCard from '../lib/ui/AuthCard.svelte';
  import Button from '../lib/ui/Button.svelte';
  import Field from '../lib/ui/Field.svelte';
  import FormError from '../lib/ui/FormError.svelte';

  let email = $state('');
  let password = $state('');
  let busy = $state(false);
  let failure = $state<ApiError | null>(null);

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    failure = null;
    try {
      await auth.login(email, password);
    } catch (e) {
      failure = e instanceof ApiRequestError ? e.error : null;
      password = '';
    } finally {
      busy = false;
    }
  }
</script>

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
</AuthCard>

<style>
  form {
    display: grid;
    gap: var(--space-4);
  }
</style>
