<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type ChannelType } from '../api/client';
  import { newSecret } from '../checks/form';
  import SecretInput from '../checks/SecretInput.svelte';
  import Button from '../ui/Button.svelte';
  import FormError from '../ui/FormError.svelte';
  import SelectField from '../ui/SelectField.svelte';
  import TextAreaField from '../ui/TextAreaField.svelte';
  import TextField from '../ui/TextField.svelte';
  import ToggleField from '../ui/ToggleField.svelte';
  import {
    CHANNEL_TYPES,
    channelFieldId,
    channelInput,
    emptyChannelForm,
    formFromChannel,
    SMTP_SECURITY,
    validateChannel,
    type ChannelErrors,
    type ChannelForm,
  } from './channels';

  interface Props {
    /** The channel being edited; absent when creating. */
    id?: string;
    onclose: (saved: boolean) => void;
  }

  let { id, onclose }: Props = $props();

  const editing = $derived(id !== undefined);
  const fid = channelFieldId;

  let form = $state<ChannelForm>(emptyChannelForm());
  let etag = $state('');
  let loading = $state(false);
  let loadError = $state<ApiError | null>(null);
  let saving = $state(false);
  let errors = $state<ChannelErrors>({});
  let failure = $state<ApiError | null>(null);
  let notice = $state('');
  let announce = $state('');

  const typeOptions = CHANNEL_TYPES.map((t) => ({ value: t.id, label: t.label }));
  const err = (p: string): string | undefined => errors[p];
  const urlLabel = $derived(
    form.type === 'webhook'
      ? 'Webhook URL'
      : `${form.type === 'teams' ? 'Teams' : form.type === 'discord' ? 'Discord' : 'Slack'} webhook URL`,
  );

  async function load(): Promise<void> {
    if (!id) return;
    loading = true;
    loadError = null;
    try {
      const r = await api.channel(id);
      form = formFromChannel(r.channel);
      etag = r.etag;
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      loadError = e.error;
    } finally {
      loading = false;
    }
  }

  onMount(() => void load());

  async function focusField(path: string): Promise<void> {
    await tick();
    document.getElementById(fid(path))?.focus();
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    failure = null;
    notice = '';
    const found = validateChannel(form);
    if (Object.keys(found).length > 0) {
      errors = found;
      await focusField(Object.keys(found)[0] as string);
      return;
    }
    errors = {};
    saving = true;
    try {
      if (editing && id) await api.updateChannel(id, channelInput(form), etag);
      else await api.createChannel(channelInput(form));
      onclose(true);
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      failure = e.error;
      if (e.error.status === 422 && e.error.field) {
        errors = { [e.error.field]: e.error.message };
        await focusField(e.error.field);
      } else if (e.error.status === 412 && id) {
        await load();
        notice =
          'This channel changed while you were editing. The latest saved version is loaded; apply your changes again.';
      }
    } finally {
      saving = false;
    }
  }

  function addHeader(): void {
    form.headers.push({ name: '', secret: false, value: '', secretValue: newSecret() });
    announce = 'Header added';
  }

  function removeHeader(i: number): void {
    form.headers.splice(i, 1);
    errors = {};
    announce = 'Header removed';
  }

  const title = $derived(editing ? 'Edit channel' : 'Add channel');
</script>

<h2 id="channel-editor-title" tabindex="-1">{title}</h2>

{#if loadError}
  <FormError error={loadError} />
{:else if loading}
  <p role="status">Loading…</p>
{:else}
  <form onsubmit={save} novalidate aria-labelledby="channel-editor-title">
    {#if failure}<FormError error={failure} />{/if}
    <p class="visually-hidden" role="status">{announce}</p>
    {#if notice}<p class="notice" role="status">{notice}</p>{/if}

    <fieldset>
      <legend>Channel</legend>
      <TextField
        id={fid('name')}
        label="Name"
        bind:value={form.name}
        error={err('name')}
        required
        maxlength={100}
        placeholder="On-call Slack"
      />
      <SelectField
        id={fid('type')}
        label="Type"
        bind:value={() => form.type, (v) => ((form.type = v as ChannelType), (errors = {}))}
        options={typeOptions}
        disabled={editing}
        hint={editing ? 'The type cannot be changed. Create a new channel instead.' : undefined}
      />
    </fieldset>

    <fieldset>
      <legend>Connection</legend>
      {#if form.type === 'smtp'}
        <div class="grid">
          <TextField
            id={fid('config.host')}
            label="Mail server"
            bind:value={form.smtp.host}
            error={err('config.host')}
            required
            mono
            placeholder="smtp.example.com"
          />
          <TextField
            id={fid('config.port')}
            label="Port"
            bind:value={form.smtp.port}
            error={err('config.port')}
            inputmode="numeric"
            hint="Blank uses the default for the security setting."
          />
        </div>
        <SelectField
          id={fid('config.security')}
          label="Security"
          bind:value={form.smtp.security}
          options={SMTP_SECURITY}
          error={err('config.security')}
        />
        <TextField
          id={fid('config.username')}
          label="User name"
          bind:value={form.smtp.username}
          autocomplete="off"
          hint="Leave blank if the server needs no sign-in."
        />
        <SecretInput
          id={fid('config.password')}
          label="Password"
          bind:draft={form.smtp.password}
          error={err('config.password')}
        />
        <TextField
          id={fid('config.from')}
          label="From address"
          bind:value={form.smtp.from}
          error={err('config.from')}
          required
          mono
          placeholder="alerts@example.com"
        />
        <TextAreaField
          id={fid('config.to')}
          label="Recipients"
          bind:value={form.smtp.to}
          error={err('config.to')}
          rows={3}
          required
          hint="One e-mail address per line or separated by commas, up to 20."
        />
      {:else if form.type === 'telegram'}
        <SecretInput
          id={fid('config.bot_token')}
          label="Bot token"
          bind:draft={form.telegram.botToken}
          error={err('config.bot_token')}
        />
        <TextField
          id={fid('config.chat_id')}
          label="Chat ID"
          bind:value={form.telegram.chatId}
          error={err('config.chat_id')}
          required
          mono
          placeholder="@mychannel"
          hint="A numeric chat ID or @channelname."
        />
      {:else}
        <SecretInput
          id={fid('config.url')}
          label={urlLabel}
          bind:draft={form.url}
          error={err('config.url')}
        />
      {/if}
    </fieldset>

    {#if form.type === 'webhook'}
      <fieldset>
        <legend>Headers</legend>
        {#if err('config.headers')}<p class="error">{err('config.headers')}</p>{/if}
        {#each form.headers as h, i (i)}
          {@const key = `config.headers[${i}]`}
          <div class="header-row">
            <TextField
              id={fid(`${key}.name`)}
              label="Header {i + 1} name"
              bind:value={h.name}
              error={err(`${key}.name`)}
              mono
              placeholder="X-Api-Key"
            />
            {#if h.secret}
              <SecretInput
                id={fid(`${key}.secret_value`)}
                label="Header {i + 1} secret value"
                bind:draft={h.secretValue}
                error={err(`${key}.secret_value`)}
              />
            {:else}
              <TextField
                id={fid(`${key}.value`)}
                label="Header {i + 1} value"
                bind:value={h.value}
                error={err(`${key}.value`)}
                mono
              />
            {/if}
            <div class="header-actions">
              <ToggleField
                id="{fid(key)}-secret"
                label="Secret"
                bind:checked={h.secret}
                hint="Stored encrypted, write-only."
              />
              <button
                type="button"
                class="link"
                aria-label="Remove header {h.name || i + 1}"
                onclick={() => removeHeader(i)}>Remove</button
              >
            </div>
          </div>
        {/each}
        <button type="button" class="link add" onclick={addHeader}>Add a header</button>
      </fieldset>
    {/if}

    <fieldset>
      <legend>Options</legend>
      <ToggleField id={fid('enabled')} label="Enabled" bind:checked={form.enabled} />
      <ToggleField
        id={fid('allow_private')}
        label="Allow private addresses"
        bind:checked={form.allowPrivate}
        hint="Lets this channel reach internal networks. Loopback and cloud metadata addresses stay blocked."
      />
      {#if form.allowPrivate}
        <p class="warning" role="note">
          Anyone who can edit this channel can make the server send requests into your private
          network. Turn this on only for a trusted internal target.
        </p>
      {/if}
    </fieldset>

    <div class="actions">
      <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save channel'}</Button>
      <Button variant="secondary" onclick={() => onclose(false)}>Cancel</Button>
    </div>
  </form>
{/if}

<style>
  h2 {
    margin-bottom: var(--space-3);
    font-size: var(--font-size-lg);
  }

  h2:focus {
    outline: none;
  }

  form {
    display: grid;
    gap: var(--space-5);
    max-width: 48rem;
  }

  fieldset {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    border: 0;
    min-width: 0;
  }

  legend {
    margin-bottom: var(--space-2);
    padding: 0;
    font-size: var(--font-size-md);
    font-weight: 700;
  }

  .grid,
  .header-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: var(--space-3);
    align-items: start;
  }

  .header-row {
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
  }

  .header-actions {
    display: grid;
    gap: var(--space-1);
  }

  .error {
    margin: 0;
    color: var(--color-status-critical);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .warning,
  .notice {
    margin: 0;
    padding: var(--space-3);
    border: 1px solid var(--color-status-warning);
    border-radius: var(--radius-1);
    background: var(--color-status-warning-bg);
    color: var(--color-status-warning);
    font-weight: 600;
  }

  .actions {
    display: flex;
    align-items: center;
    gap: var(--space-3);
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
