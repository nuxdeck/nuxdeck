<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { api, ApiRequestError, type ApiError, type OidcSettings } from '../api/client';
  import { oidcInput } from '../sso';
  import Button from './Button.svelte';
  import Field from './Field.svelte';
  import FormError from './FormError.svelte';
  import ToggleField from './ToggleField.svelte';

  let current = $state<OidcSettings | null>(null);
  let issuer = $state('');
  let clientId = $state('');
  let clientSecret = $state('');
  let scopes = $state('openid email profile');
  let groupsClaim = $state('groups');
  let allowedDomains = $state('');
  let autoProvision = $state(false);
  let linkExisting = $state(false);
  let busy = $state(false);
  let saved = $state(false);
  let error = $state<ApiError | null>(null);

  function fill(s: OidcSettings): void {
    current = s;
    if (!s.configured) return;
    issuer = s.issuer;
    clientId = s.client_id;
    scopes = s.scopes.join(' ');
    groupsClaim = s.groups_claim;
    allowedDomains = s.allowed_domains.join(', ');
    autoProvision = s.auto_provision;
    linkExisting = s.link_existing;
  }

  async function load(): Promise<void> {
    try {
      fill(await api.oidcSettings());
      error = null;
    } catch (e) {
      if (e instanceof ApiRequestError) error = e.error;
    }
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    busy = true;
    saved = false;
    try {
      const input = oidcInput({
        issuer,
        clientId,
        clientSecret,
        scopes,
        groupsClaim,
        allowedDomains,
        autoProvision,
        linkExisting,
      });
      fill(await api.saveOidcSettings(input));
      clientSecret = '';
      saved = true;
      error = null;
    } catch (e) {
      if (e instanceof ApiRequestError) error = e.error;
    } finally {
      busy = false;
    }
  }

  async function remove(): Promise<void> {
    if (!window.confirm('Remove single sign-on? People will sign in with passwords only.')) return;
    busy = true;
    try {
      await api.deleteOidcSettings();
      current = null;
      issuer = clientId = clientSecret = allowedDomains = '';
      autoProvision = linkExisting = false;
      error = null;
    } catch (e) {
      if (e instanceof ApiRequestError) error = e.error;
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<section aria-labelledby="sso-heading">
  <h2 id="sso-heading">Single sign-on</h2>
  <p>
    Sign people in with one OpenID Connect provider, such as Google, Microsoft Entra ID, Okta,
    Keycloak or GitHub. Map a provider group to a role on the role bindings page, with the subject
    type oidc_group.
  </p>
  {#if current?.configured}
    <p>Register this redirect URI with the provider: <code>{current.redirect_uri}</code></p>
  {/if}
  {#if error}<FormError {error} />{/if}
  <form onsubmit={save}>
    <Field
      id="sso-issuer"
      label="Issuer URL"
      bind:value={issuer}
      disabled={busy}
      hint="The https address of your identity provider, as shown in its discovery document"
    />
    <Field id="sso-client-id" label="Client ID" bind:value={clientId} disabled={busy} />
    <Field
      id="sso-client-secret"
      label="Client secret"
      type="password"
      bind:value={clientSecret}
      autocomplete="off"
      disabled={busy}
      hint={current?.client_secret_set
        ? 'Stored and never shown again. Leave blank to keep it.'
        : 'Needed the first time.'}
    />
    <Field
      id="sso-scopes"
      label="Scopes"
      bind:value={scopes}
      disabled={busy}
      hint="Separate with spaces or commas. openid is always included."
    />
    <Field
      id="sso-groups-claim"
      label="Groups claim"
      bind:value={groupsClaim}
      disabled={busy}
      hint="The ID token claim that lists a person's groups."
    />
    <Field
      id="sso-domains"
      label="Allowed email domains"
      bind:value={allowedDomains}
      disabled={busy}
      hint="Optional. Leave empty to allow any domain."
    />
    <ToggleField
      id="sso-auto-provision"
      label="Create an account on first sign-in"
      hint="Without this, only people who already have an account can sign in."
      bind:checked={autoProvision}
      disabled={busy}
    />
    <ToggleField
      id="sso-link-existing"
      label="Link an existing account with the same verified email"
      hint="Off by default, so an email address cannot take over an account."
      bind:checked={linkExisting}
      disabled={busy}
    />
    <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save single sign-on'}</Button>
    {#if current?.configured}
      <Button variant="secondary" onclick={remove} disabled={busy}>Remove single sign-on</Button>
    {/if}
  </form>
  {#if saved}<p role="status">Saved.</p>{/if}
</section>

<style>
  section {
    display: grid;
    gap: var(--space-3);
    max-width: 48rem;
  }

  form {
    display: grid;
    gap: var(--space-4);
  }
</style>
