<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { ApiRequestError, type ApiError } from '../lib/api/client';
  import { auth } from '../lib/auth.svelte';
  import { passwordFeedback } from '../lib/password';
  import AuthCard from '../lib/ui/AuthCard.svelte';
  import Button from '../lib/ui/Button.svelte';
  import Field from '../lib/ui/Field.svelte';
  import FormError from '../lib/ui/FormError.svelte';

  let token = $state('');
  let name = $state('');
  let email = $state('');
  let password = $state('');
  let busy = $state(false);
  let failure = $state<ApiError | null>(null);

  const feedback = $derived(passwordFeedback(password));
  const fieldError = (field: string): string | undefined =>
    failure?.field === field ? `${failure.message} ${failure.hint}` : undefined;

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    failure = null;
    try {
      await auth.completeSetup({ token, name, email, password });
    } catch (e) {
      failure = e instanceof ApiRequestError ? e.error : null;
    } finally {
      busy = false;
    }
  }
</script>

<AuthCard
  title="Set up Nux Deck"
  intro="Step 1 of 5: create the administrator account. All fields are required."
>
  <form onsubmit={submit}>
    {#if failure && !failure.field}<FormError error={failure} />{/if}
    <Field
      id="token"
      label="Setup token"
      bind:value={token}
      autocomplete="off"
      disabled={busy}
      hint="Run “nuxd setup-token” on the server (in a container: docker exec <name> nuxd setup-token)."
    />
    <Field
      id="name"
      label="Your name"
      bind:value={name}
      autocomplete="name"
      disabled={busy}
      error={fieldError('name')}
    />
    <Field
      id="email"
      label="Email"
      type="email"
      bind:value={email}
      autocomplete="username"
      disabled={busy}
      error={fieldError('email')}
    />
    <div class="password">
      <Field
        id="password"
        label="Password"
        type="password"
        bind:value={password}
        autocomplete="new-password"
        disabled={busy}
        error={fieldError('password')}
      />
      <p class="strength" class:ok={feedback.ok} aria-live="polite">{feedback.message}</p>
    </div>
    <Button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create administrator'}</Button>
  </form>
</AuthCard>

<style>
  form {
    display: grid;
    gap: var(--space-4);
  }

  .password {
    display: grid;
    gap: var(--space-1);
  }

  .strength {
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }

  .strength.ok {
    color: var(--color-status-healthy);
    font-weight: 600;
  }
</style>
