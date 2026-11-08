<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { parseCustomRange, PRESETS, toLocalInput, type RangeSelection } from '../metrics/range';

  interface Props {
    value: RangeSelection;
    onchange: (next: RangeSelection) => void;
  }

  let { value, onchange }: Props = $props();

  let customOpen = $state(false);
  let fromInput = $state('');
  let toInput = $state('');
  let problem = $state<{ field: 'from' | 'to'; message: string } | null>(null);
  const uid = $props.id();

  function openCustom(): void {
    if (!fromInput || !toInput) {
      const now = Date.now();
      toInput = toLocalInput(now);
      fromInput = toLocalInput(now - 3_600_000);
    }
    customOpen = true;
  }

  function apply(event: SubmitEvent): void {
    event.preventDefault();
    const result = parseCustomRange(fromInput, toInput, Date.now());
    if (!result.ok) {
      problem = { field: result.field, message: result.message };
      return;
    }
    problem = null;
    onchange(result.range);
  }

  // Arrow keys move between the options like a radio group, as the buttons act as one control.
  function onkeydown(event: KeyboardEvent): void {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    const buttons = Array.from(
      (event.currentTarget as HTMLElement).querySelectorAll<HTMLButtonElement>('button'),
    );
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (at < 0) return;
    event.preventDefault();
    const step = event.key === 'ArrowRight' ? 1 : -1;
    buttons[(at + step + buttons.length) % buttons.length]?.focus();
  }
</script>

<div class="picker">
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div class="options" role="group" aria-label="Time range" {onkeydown}>
    {#each PRESETS as p (p.id)}
      <button
        type="button"
        aria-pressed={value.kind === 'preset' && value.id === p.id}
        onclick={() => {
          customOpen = false;
          problem = null;
          onchange({ kind: 'preset', id: p.id });
        }}>{p.id}</button
      >
    {/each}
    <button
      type="button"
      aria-pressed={value.kind === 'custom'}
      aria-expanded={customOpen}
      aria-controls="{uid}-custom"
      onclick={() => (customOpen ? (customOpen = false) : openCustom())}>Custom</button
    >
  </div>

  {#if customOpen}
    <form id="{uid}-custom" class="custom" onsubmit={apply} novalidate>
      <label>
        From
        <input
          type="datetime-local"
          bind:value={fromInput}
          aria-invalid={problem?.field === 'from'}
          aria-describedby={problem ? `${uid}-problem` : undefined}
        />
      </label>
      <label>
        To
        <input
          type="datetime-local"
          bind:value={toInput}
          aria-invalid={problem?.field === 'to'}
          aria-describedby={problem ? `${uid}-problem` : undefined}
        />
      </label>
      <button type="submit" class="apply">Apply</button>
      {#if problem}
        <p id="{uid}-problem" class="problem" role="alert">{problem.message}</p>
      {/if}
    </form>
  {/if}
</div>

<style>
  .picker {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: var(--space-3);
  }

  .options {
    display: inline-flex;
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    overflow: hidden;
  }

  button {
    min-height: var(--target-size);
    padding: 0 var(--space-3);
    border: 0;
    background: var(--color-surface);
    color: var(--color-text);
    font-weight: 600;
    cursor: pointer;
  }

  .options button + button {
    border-left: 1px solid var(--color-border-strong);
  }

  button[aria-pressed='true'] {
    background: var(--color-accent);
    color: var(--color-accent-text);
  }

  .custom {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--space-2);
  }

  label {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
  }

  input {
    min-height: var(--target-size);
    padding: 0 var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
    font: inherit;
  }

  .apply {
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
  }

  .problem {
    flex-basis: 100%;
    margin: 0;
    color: var(--color-status-critical);
    font-size: var(--font-size-sm);
  }
</style>
