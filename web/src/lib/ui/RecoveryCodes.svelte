<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import Button from './Button.svelte';

  let { codes, onDone }: { codes: string[]; onDone: () => void } = $props();
  let saved = $state(false);
</script>

<div class="codes">
  <p>
    Each code works once if you lose your authenticator. They are shown only now, so store them
    somewhere safe.
  </p>
  <ul aria-label="Recovery codes">
    {#each codes as code (code)}<li><code>{code}</code></li>{/each}
  </ul>
  <label class="ack">
    <input type="checkbox" bind:checked={saved} />
    I have saved these codes
  </label>
  <Button onclick={onDone} disabled={!saved}>Continue</Button>
</div>

<style>
  .codes {
    display: grid;
    gap: var(--space-3);
  }

  ul {
    list-style: none;
    margin: 0;
    padding: var(--space-3);
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(12ch, 1fr));
    gap: var(--space-2);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
  }

  .ack {
    display: flex;
    gap: var(--space-2);
    align-items: center;
  }
</style>
