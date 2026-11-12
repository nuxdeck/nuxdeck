<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { UNIT_PATTERN } from '../logs';
  import Button from './Button.svelte';
  import LogViewer from './LogViewer.svelte';

  let { hostId }: { hostId: string } = $props();

  let unit = $state('');
  let active = $state('');
  const trimmed = $derived(unit.trim());
  const invalid = $derived(trimmed !== '' && !UNIT_PATTERN.test(trimmed));

  function open(event: SubmitEvent): void {
    event.preventDefault();
    if (trimmed !== '' && !invalid) active = trimmed;
  }
</script>

<form onsubmit={open} class="unit">
  <div class="field">
    <label for="journal-unit">Journal unit</label>
    <input
      id="journal-unit"
      type="text"
      autocomplete="off"
      spellcheck="false"
      placeholder="sshd.service"
      bind:value={unit}
      aria-invalid={invalid ? 'true' : undefined}
      aria-describedby={invalid ? 'journal-unit-error' : undefined}
    />
  </div>
  <Button type="submit" disabled={trimmed === '' || invalid}>View logs</Button>
</form>
{#if invalid}
  <p id="journal-unit-error" class="problem">
    Use letters, digits and : _ . @ - only, starting with a letter or digit.
  </p>
{/if}
{#if active}
  {#key active}
    <LogViewer target="journal:{hostId}:{active}" />
  {/key}
{:else}
  <p class="hint">Enter a systemd unit name to follow its journal.</p>
{/if}

<style>
  .unit {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  input {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
  }

  .problem {
    color: var(--color-status-critical);
    font-weight: 600;
  }

  .hint {
    color: var(--color-text-muted);
  }
</style>
