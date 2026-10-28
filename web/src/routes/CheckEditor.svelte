<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, ApiRequestError, type ApiError, type CheckType } from '../lib/api/client';
  import { canWriteChecks, runnerLabel } from '../lib/checks/access';
  import {
    CHECK_TYPES,
    emptyForm,
    fieldId,
    formFromCheck,
    HTTP_METHODS,
    newSecret,
    RECORD_TYPES,
    SERVER_RUNNER,
    toInput,
    URL_HINT,
    validate,
    type CheckForm,
    type FormErrors,
  } from '../lib/checks/form';
  import SecretInput from '../lib/checks/SecretInput.svelte';
  import { inventory } from '../lib/inventory.svelte';
  import { router } from '../lib/router.svelte';
  import Button from '../lib/ui/Button.svelte';
  import EmptyState from '../lib/ui/EmptyState.svelte';
  import FormError from '../lib/ui/FormError.svelte';
  import SelectField from '../lib/ui/SelectField.svelte';
  import TextField from '../lib/ui/TextField.svelte';
  import ToggleField from '../lib/ui/ToggleField.svelte';

  /** The check being edited; absent when creating. */
  let { id }: { id?: string } = $props();

  const editing = $derived(id !== undefined);
  const canWrite = $derived(canWriteChecks());

  let form = $state<CheckForm>(emptyForm());
  let etag = $state('');
  let loading = $state(false);
  let missing = $state(false);
  let loadError = $state<ApiError | null>(null);
  let saving = $state(false);
  let errors = $state<FormErrors>({});
  let failure = $state<ApiError | null>(null);
  let notice = $state('');
  let announce = $state('');
  let advancedOpen = $state(false);

  const ADVANCED = [
    'allow_private',
    'http.verify_tls',
    'http.max_redirects',
    'http.max_body_bytes',
  ];

  const typeOptions = CHECK_TYPES.map((t) => ({ value: t.id, label: t.label }));
  const methodOptions = HTTP_METHODS.map((m) => ({ value: m, label: m }));
  const recordOptions = RECORD_TYPES.map((r) => ({ value: r, label: r }));
  const authOptions = [
    { value: 'none', label: 'None' },
    { value: 'basic', label: 'Basic (user name and password)' },
    { value: 'bearer', label: 'Bearer token' },
  ];
  const jsonOpOptions = [
    { value: 'exists', label: 'exists' },
    { value: 'equals', label: 'equals' },
  ];

  const runnerOptions = $derived.by(() => {
    const options = [{ value: SERVER_RUNNER, label: 'Server (nuxd)' }];
    for (const h of inventory.hosts) {
      if (h.agent_id && !options.some((o) => o.value === h.agent_id)) {
        options.push({ value: h.agent_id, label: `Agent on ${h.hostname}` });
      }
    }
    if (!options.some((o) => o.value === form.runner)) {
      options.push({ value: form.runner, label: runnerLabel(form.runner, inventory.hosts) });
    }
    return options;
  });

  const title = $derived(editing ? 'Edit check' : 'Add check');

  $effect(() => {
    router.titleOverride = editing && form.name ? `Edit ${form.name}` : title;
  });

  async function load(): Promise<void> {
    if (!id) return;
    loading = true;
    loadError = null;
    try {
      const loaded = await api.check(id);
      form = formFromCheck(loaded.check);
      etag = loaded.etag;
    } catch (e) {
      if (e instanceof ApiRequestError && e.error.status === 404) missing = true;
      else if (e instanceof ApiRequestError) loadError = e.error;
      else throw e;
    } finally {
      loading = false;
    }
  }

  onMount(() => void load());

  async function focusFirst(keys: string[]): Promise<void> {
    await tick();
    document.getElementById(fieldId(keys[0]!))?.focus();
  }

  function orderedKeys(e: FormErrors): string[] {
    // Page order: the DOM decides, so ask it rather than keep a second list in step with the template.
    const keys = Object.keys(e);
    const position = (k: string): number => {
      const el = document.getElementById(fieldId(k));
      return el ? Array.from(document.querySelectorAll('form *')).indexOf(el) : Infinity;
    };
    return keys.sort((a, b) => position(a) - position(b));
  }

  function show(e: FormErrors): void {
    errors = e;
    if (ADVANCED.some((k) => k in e)) advancedOpen = true;
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    failure = null;
    notice = '';
    const found = validate(form);
    if (Object.keys(found).length > 0) {
      show(found);
      await tick();
      await focusFirst(orderedKeys(found));
      return;
    }
    errors = {};
    saving = true;
    try {
      const saved =
        editing && id
          ? await api.updateCheck(id, toInput(form), etag)
          : await api.createCheck(toInput(form));
      router.navigate(`/checks/${saved.check.id}`);
    } catch (e) {
      if (!(e instanceof ApiRequestError)) throw e;
      await handleFailure(e.error);
    } finally {
      saving = false;
    }
  }

  async function handleFailure(error: ApiError): Promise<void> {
    failure = error;
    if (error.status === 422 && error.field) {
      show({ [error.field]: error.message });
      await focusFirst([error.field]);
    } else if (error.status === 412 && id) {
      // Someone else saved first: show what is stored now so the change is made against it.
      await load();
      notice =
        'This check changed while you were editing. The latest saved version is loaded; apply your changes again.';
    }
    // 428 (If-Match missing) and everything else show the server's message and hint as they are.
  }

  function addHeader(): void {
    form.http.headers.push({ name: '', secret: false, value: '', secretValue: newSecret() });
  }

  function removeHeader(i: number): void {
    form.http.headers.splice(i, 1);
    errors = {};
    announce = 'Header removed';
  }

  const err = (path: string): string | undefined => errors[path];
</script>

<nav class="crumbs" aria-label="Breadcrumb">
  <a href="/checks">Checks</a> / {title}
</nav>
<h1 id="page-title" tabindex="-1">{title}</h1>

{#if !canWrite}
  <EmptyState title="Operator access needed">
    Your account can view checks but not change them. Ask an administrator for the operator role.
  </EmptyState>
{:else if missing}
  <EmptyState title="Check not found">
    This check does not exist, or it was deleted. Go back to the <a href="/checks">checks</a>.
  </EmptyState>
{:else if loadError}
  <FormError error={loadError} />
{:else if loading}
  <p role="status">Loading…</p>
{:else}
  <form onsubmit={save} novalidate aria-label={title}>
    {#if failure}<FormError error={failure} />{/if}
    <p class="visually-hidden" role="status">{announce}</p>
    {#if notice}<p class="notice" role="status">{notice}</p>{/if}

    <fieldset>
      <legend>What to check</legend>
      <TextField
        id={fieldId('name')}
        label="Name"
        bind:value={form.name}
        error={err('name')}
        required
        maxlength={100}
        placeholder="Public website"
      />
      <SelectField
        id={fieldId('type')}
        label="Type"
        bind:value={() => form.type, (v) => (form.type = v as CheckType)}
        options={typeOptions}
        error={err('type')}
        onchange={() => (errors = {})}
      />
      <SelectField
        id={fieldId('runner')}
        label="Runs from"
        bind:value={form.runner}
        options={runnerOptions}
        error={err('runner')}
        hint="The server checks from where nuxd runs. An agent checks from its own host, which can reach private networks."
      />
    </fieldset>

    {#if form.type === 'http'}
      <fieldset>
        <legend>HTTP request</legend>
        <TextField
          id={fieldId('http.url')}
          label="URL"
          bind:value={form.http.url}
          error={err('http.url')}
          required
          mono
          placeholder="example.com/health"
          hint={URL_HINT}
        />
        <SelectField
          id={fieldId('http.method')}
          label="Method"
          bind:value={form.http.method}
          options={methodOptions}
          error={err('http.method')}
        />
        {#if form.http.method !== 'GET' && form.http.method !== 'HEAD'}
          <div class="field">
            <label for={fieldId('http.body')}>Request body</label>
            <textarea
              id={fieldId('http.body')}
              rows="3"
              bind:value={form.http.body}
              spellcheck="false"
              aria-invalid={err('http.body') ? 'true' : undefined}
              aria-describedby={err('http.body') ? `${fieldId('http.body')}-error` : undefined}
            ></textarea>
            {#if err('http.body')}
              <p id="{fieldId('http.body')}-error" class="error">{err('http.body')}</p>
            {/if}
          </div>
        {/if}
      </fieldset>

      <fieldset>
        <legend>Headers</legend>
        {#if err('http.headers')}<p class="error">{err('http.headers')}</p>{/if}
        {#each form.http.headers as h, i (i)}
          {@const key = `http.headers[${i}]`}
          <div class="header-row">
            <TextField
              id={fieldId(`${key}.name`)}
              label="Header {i + 1} name"
              bind:value={h.name}
              error={err(`${key}.name`)}
              mono
              placeholder="X-Api-Key"
            />
            {#if h.secret}
              <SecretInput
                id={fieldId(`${key}.secret_value`)}
                label="Header {i + 1} secret value"
                bind:draft={h.secretValue}
                error={err(`${key}.secret_value`)}
              />
            {:else}
              <TextField
                id={fieldId(`${key}.value`)}
                label="Header {i + 1} value"
                bind:value={h.value}
                error={err(`${key}.value`)}
                mono
              />
            {/if}
            <div class="header-actions">
              <ToggleField
                id="{fieldId(key)}-secret"
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

      <fieldset>
        <legend>Authentication</legend>
        <SelectField
          id={fieldId('http.auth.type')}
          label="Type"
          bind:value={
            () => form.http.authType,
            (v) => (form.http.authType = v as CheckForm['http']['authType'])
          }
          options={authOptions}
          error={err('http.auth.type')}
        />
        {#if form.http.authType === 'basic'}
          <TextField
            id={fieldId('http.auth.username')}
            label="User name"
            bind:value={form.http.username}
            error={err('http.auth.username')}
            required
            autocomplete="off"
          />
          <SecretInput
            id={fieldId('http.auth.password')}
            label="Password"
            bind:draft={form.http.password}
            error={err('http.auth.password')}
          />
        {:else if form.http.authType === 'bearer'}
          <SecretInput
            id={fieldId('http.auth.token')}
            label="Token"
            bind:draft={form.http.token}
            error={err('http.auth.token')}
          />
        {/if}
      </fieldset>

      <fieldset>
        <legend>What counts as up</legend>
        <TextField
          id={fieldId('http.expected_status')}
          label="Expected status codes"
          bind:value={form.http.expectedStatus}
          error={err('http.expected_status')}
          inputmode="numeric"
          placeholder="200, 204"
          hint="Leave blank to accept any 2xx or 3xx response."
        />
        <TextField
          id={fieldId('http.keyword')}
          label="Response must contain"
          bind:value={form.http.keyword}
          error={err('http.keyword')}
          maxlength={256}
        />
        <ToggleField
          id={fieldId('http.json-enabled')}
          label="Match a value in a JSON response"
          bind:checked={form.http.jsonEnabled}
        />
        {#if form.http.jsonEnabled}
          <div class="json-row">
            <TextField
              id={fieldId('http.json.path')}
              label="JSON path"
              bind:value={form.http.jsonPath}
              error={err('http.json.path')}
              mono
              placeholder="status.ok"
              hint="For example a.b[0].c"
            />
            <SelectField
              id={fieldId('http.json.op')}
              label="Condition"
              bind:value={
                () => form.http.jsonOp, (v) => (form.http.jsonOp = v as 'exists' | 'equals')
              }
              options={jsonOpOptions}
              error={err('http.json.op')}
            />
            {#if form.http.jsonOp === 'equals'}
              <TextField
                id={fieldId('http.json.value')}
                label="Expected value"
                bind:value={form.http.jsonValue}
                error={err('http.json.value')}
                maxlength={256}
              />
            {/if}
          </div>
        {/if}
      </fieldset>
    {:else if form.type === 'tcp'}
      <fieldset>
        <legend>TCP connection</legend>
        <TextField
          id={fieldId('tcp.host')}
          label="Host"
          bind:value={form.tcp.host}
          error={err('tcp.host')}
          required
          mono
          hint="A host name or IP address."
        />
        <TextField
          id={fieldId('tcp.port')}
          label="Port"
          bind:value={form.tcp.port}
          error={err('tcp.port')}
          required
          inputmode="numeric"
        />
      </fieldset>
    {:else if form.type === 'dns'}
      <fieldset>
        <legend>DNS lookup</legend>
        <TextField
          id={fieldId('dns.name')}
          label="Name"
          bind:value={form.dns.name}
          error={err('dns.name')}
          required
          mono
        />
        <SelectField
          id={fieldId('dns.record_type')}
          label="Record type"
          bind:value={form.dns.recordType}
          options={recordOptions}
          error={err('dns.record_type')}
        />
        <TextField
          id={fieldId('dns.resolver')}
          label="Resolver"
          bind:value={form.dns.resolver}
          error={err('dns.resolver')}
          mono
          placeholder="9.9.9.9:53"
          hint="host:port. Leave blank to use the system resolver."
        />
        <div class="field">
          <label for={fieldId('dns.expected')}>Expected values</label>
          <textarea
            id={fieldId('dns.expected')}
            rows="3"
            bind:value={form.dns.expected}
            spellcheck="false"
            aria-describedby="{fieldId('dns.expected')}-hint{err('dns.expected')
              ? ` ${fieldId('dns.expected')}-error`
              : ''}"
            aria-invalid={err('dns.expected') ? 'true' : undefined}></textarea>
          <p id="{fieldId('dns.expected')}-hint" class="hint">
            One per line, up to 10. Every value must be in the answer. Leave blank to only require
            an answer.
          </p>
          {#if err('dns.expected')}
            <p id="{fieldId('dns.expected')}-error" class="error">{err('dns.expected')}</p>
          {/if}
        </div>
      </fieldset>
    {:else if form.type === 'tls'}
      <fieldset>
        <legend>TLS certificate</legend>
        <TextField
          id={fieldId('tls.host')}
          label="Host"
          bind:value={form.tls.host}
          error={err('tls.host')}
          required
          mono
        />
        <TextField
          id={fieldId('tls.port')}
          label="Port"
          bind:value={form.tls.port}
          error={err('tls.port')}
          inputmode="numeric"
        />
        <TextField
          id={fieldId('tls.server_name')}
          label="Server name (SNI)"
          bind:value={form.tls.serverName}
          error={err('tls.server_name')}
          mono
          hint="Only when it differs from the host."
        />
        <TextField
          id={fieldId('tls.warn_days')}
          label="Warn when it expires within (days)"
          bind:value={form.tls.warnDays}
          error={err('tls.warn_days')}
          inputmode="numeric"
        />
        <ToggleField
          id={fieldId('tls.verify_chain')}
          label="Verify the certificate chain"
          bind:checked={form.tls.verifyChain}
        />
      </fieldset>
    {:else}
      <fieldset>
        <legend>Ping</legend>
        <TextField
          id={fieldId('ping.host')}
          label="Host"
          bind:value={form.ping.host}
          error={err('ping.host')}
          required
          mono
        />
        <TextField
          id={fieldId('ping.count')}
          label="Packets per run (1 to 5)"
          bind:value={form.ping.count}
          error={err('ping.count')}
          inputmode="numeric"
        />
      </fieldset>
    {/if}

    <fieldset>
      <legend>Schedule</legend>
      <div class="grid">
        <TextField
          id={fieldId('interval_s')}
          label="Interval (seconds)"
          bind:value={form.interval}
          error={err('interval_s')}
          required
          inputmode="numeric"
          hint="20 to 86400."
        />
        <TextField
          id={fieldId('timeout_s')}
          label="Timeout (seconds)"
          bind:value={form.timeout}
          error={err('timeout_s')}
          required
          inputmode="numeric"
          hint="1 to 60, shorter than the interval."
        />
        <TextField
          id={fieldId('retries')}
          label="Retries before down"
          bind:value={form.retries}
          error={err('retries')}
          inputmode="numeric"
          hint="0 to 5."
        />
      </div>
      <ToggleField id={fieldId('enabled')} label="Enabled" bind:checked={form.enabled} />
    </fieldset>

    <details bind:open={advancedOpen}>
      <summary>Advanced options</summary>
      <div class="advanced">
        <ToggleField
          id={fieldId('allow_private')}
          label="Allow private and internal addresses"
          bind:checked={form.allowPrivate}
          hint="Off by default. When on, this check may reach loopback, private (10.x, 172.16.x, 192.168.x), link-local and cloud metadata addresses, so a mistyped target can probe your internal network. Turn it on only for targets you control."
        />
        {#if form.type === 'http'}
          <ToggleField
            id={fieldId('http.verify_tls')}
            label="Verify the TLS certificate"
            bind:checked={form.http.verifyTls}
            hint="Turning this off accepts expired or self-signed certificates."
          />
          <TextField
            id={fieldId('http.max_redirects')}
            label="Maximum redirects"
            bind:value={form.http.maxRedirects}
            error={err('http.max_redirects')}
            inputmode="numeric"
            hint="0 to 10."
          />
          <TextField
            id={fieldId('http.max_body_bytes')}
            label="Maximum response body read (bytes)"
            bind:value={form.http.maxBodyBytes}
            error={err('http.max_body_bytes')}
            inputmode="numeric"
            hint="1 to 1048576. Only matters when matching content."
          />
        {/if}
      </div>
    </details>

    <div class="actions">
      <Button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Save check'}</Button>
      <a class="cancel" href={editing && id ? `/checks/${id}` : '/checks'}>Cancel</a>
    </div>
  </form>
{/if}

<style>
  .crumbs {
    margin-bottom: var(--space-2);
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  h1 {
    margin-bottom: var(--space-4);
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  form {
    display: grid;
    gap: var(--space-5);
    max-width: 44rem;
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

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: var(--space-3);
  }

  .header-row,
  .json-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
    gap: var(--space-3);
    align-items: start;
    padding: var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
  }

  .json-row {
    border: 0;
    padding: 0;
  }

  .header-actions {
    display: grid;
    gap: var(--space-1);
  }

  .field {
    display: grid;
    gap: var(--space-1);
  }

  label {
    font-weight: 600;
  }

  textarea {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
    font-family: var(--font-mono);
  }

  textarea[aria-invalid='true'] {
    border-color: var(--color-status-critical);
  }

  summary {
    min-height: var(--target-size);
    display: flex;
    align-items: center;
    cursor: pointer;
    font-weight: 700;
  }

  .advanced {
    display: grid;
    gap: var(--space-3);
    padding-top: var(--space-2);
  }

  .hint {
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

  .cancel {
    display: inline-flex;
    align-items: center;
    min-height: var(--target-size);
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
