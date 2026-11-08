<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import { LogStream } from '../logstream.svelte';
  import { compileFilter, MAX_PATTERN_CHARS } from '../logs';
  import Button from './Button.svelte';

  let { target, tail = 100 }: { target: string; tail?: number } = $props();

  const ROW_HEIGHT = 20;
  const OVERSCAN = 20;
  const FALLBACK_VIEW = 400;

  const stream = new LogStream();

  let pattern = $state('');
  let mode = $state<'text' | 'regex'>('text');
  let showTime = $state(false);
  let wrap = $state(false);
  let following = $state(true);
  let scrollTop = $state(0);
  let viewHeight = $state(0);
  let region = $state<HTMLDivElement>();
  let topSpacer = $state<HTMLDivElement>();
  let bottomSpacer = $state<HTMLDivElement>();

  const filter = $derived(compileFilter(pattern, mode));
  const visible = $derived.by(() => {
    void stream.version;
    const test = filter.test;
    const lines = stream.buffer.lines;
    // Always a new array: the buffer is mutated in place, and dependants compare by reference.
    return test ? lines.filter(test) : lines.slice();
  });

  // Wrapped rows have no fixed height, so only the unwrapped view is windowed; the buffer bound keeps
  // the wrapped view to at most BUFFER_LINES rows.
  const windowed = $derived(!wrap);
  const range = $derived.by(() => {
    if (!windowed) return { start: 0, end: visible.length };
    const view = viewHeight || FALLBACK_VIEW;
    const start = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
    const end = Math.min(visible.length, Math.ceil((scrollTop + view) / ROW_HEIGHT) + OVERSCAN);
    return { start, end };
  });
  const rows = $derived(visible.slice(range.start, range.end));

  $effect(() => {
    if (topSpacer) topSpacer.style.height = windowed ? `${range.start * ROW_HEIGHT}px` : '0';
    if (bottomSpacer)
      bottomSpacer.style.height = windowed ? `${(visible.length - range.end) * ROW_HEIGHT}px` : '0';
  });

  $effect(() => {
    void visible;
    if (following && region) {
      void tick().then(() => {
        if (region) region.scrollTop = region.scrollHeight;
      });
    }
  });

  $effect(() => {
    if (region) viewHeight = region.clientHeight;
  });

  $effect(() => {
    stream.connect(target, tail);
    return () => stream.close();
  });
  onDestroy(() => stream.close());

  function onscroll(): void {
    if (!region) return;
    scrollTop = region.scrollTop;
    viewHeight = region.clientHeight;
    following = region.scrollHeight - region.scrollTop - region.clientHeight < ROW_HEIGHT * 1.5;
  }

  function jump(): void {
    following = true;
    if (region) region.scrollTop = region.scrollHeight;
  }

  function clock(ts: number): string {
    const d = new Date(ts);
    return Number.isNaN(d.getTime()) ? '' : d.toISOString().slice(11, 23);
  }

  const canReconnect = $derived(stream.state === 'ended' || stream.state === 'error');
  const stateLabel = $derived(
    { idle: 'Idle', connecting: 'Connecting', live: 'Live', ended: 'Ended', error: 'Error' }[
      stream.state
    ],
  );
</script>

<div class="viewer">
  <div class="toolbar">
    <div class="field">
      <label for="log-filter">Filter</label>
      <input
        id="log-filter"
        type="search"
        autocomplete="off"
        spellcheck="false"
        maxlength={MAX_PATTERN_CHARS + 50}
        bind:value={pattern}
        aria-invalid={filter.error ? 'true' : undefined}
        aria-describedby={filter.error ? 'log-filter-error' : undefined}
      />
    </div>
    <div class="field">
      <label for="log-mode">Match as</label>
      <select id="log-mode" bind:value={mode}>
        <option value="text">Text</option>
        <option value="regex">Regular expression</option>
      </select>
    </div>
    <label class="check"><input type="checkbox" bind:checked={showTime} /> Timestamps</label>
    <label class="check"><input type="checkbox" bind:checked={wrap} /> Wrap lines</label>
    <Button variant="secondary" onclick={() => (stream.paused ? stream.resume() : stream.pause())}>
      {stream.paused ? `Resume${stream.unseen > 0 ? ` (${stream.unseen} new)` : ''}` : 'Pause'}
    </Button>
    <Button variant="secondary" onclick={() => stream.clear()}>Clear</Button>
    {#if canReconnect}<Button onclick={() => stream.reconnect()}>Reconnect</Button>{/if}
  </div>
  {#if filter.error}
    <p id="log-filter-error" class="problem">{filter.error}</p>
  {/if}

  <p class="state"><strong>{stateLabel}</strong></p>
  <p class="status" role="status" aria-live="polite">{stream.statusText}</p>
  {#if stream.state === 'error' && stream.errorCode}
    <p class="problem">{stream.errorCode}: {stream.statusText}</p>
  {/if}

  <div class="frame">
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <!-- A scrollable region must be keyboard-focusable so it can be scrolled without a pointer. -->
    <div
      class="region"
      role="log"
      aria-live="off"
      aria-label="Log output"
      tabindex="0"
      bind:this={region}
      {onscroll}
    >
      <div bind:this={topSpacer}></div>
      {#each rows as line (line.id)}
        <div class="row lvl-{line.level} stream-{line.stream}" class:wrap>
          {#if showTime && line.stream !== 'notice'}<span class="ts">{clock(line.ts)}</span>{/if}
          {#if line.stream === 'stderr'}<span class="tag">stderr</span>{/if}
          {#if line.stream === 'notice'}<span class="tag">notice</span>{/if}
          <span class="msg">{line.text}</span>
        </div>
      {/each}
      <div bind:this={bottomSpacer}></div>
      {#if visible.length === 0}
        <p class="empty">
          {stream.buffer.lines.length > 0 ? 'No lines match the filter.' : 'No log lines yet.'}
        </p>
      {/if}
    </div>
    {#if !following}
      <button type="button" class="jump" onclick={jump}>Jump to latest</button>
    {/if}
  </div>
</div>

<style>
  .viewer {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: end;
    gap: var(--space-3);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    font-size: var(--font-size-sm);
  }

  input[type='search'],
  select {
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-2);
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface);
    color: var(--color-text);
  }

  .check {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    min-height: var(--target-size);
  }

  .state,
  .status {
    margin: 0;
    color: var(--color-text-muted);
    font-size: var(--font-size-sm);
  }

  .problem {
    margin: 0;
    color: var(--color-status-critical);
    font-weight: 600;
  }

  .frame {
    position: relative;
  }

  .region {
    height: 60vh;
    min-height: 240px;
    overflow: auto;
    border: 1px solid var(--color-border-strong);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
    color: var(--color-text);
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }

  .row {
    min-height: 20px;
    line-height: 20px;
    padding: 0 var(--space-2);
    border-left: 3px solid transparent;
    white-space: pre;
  }

  .row.wrap {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }

  .ts,
  .tag {
    margin-right: var(--space-2);
    color: var(--color-text-muted);
  }

  .tag {
    font-weight: 700;
    text-transform: uppercase;
  }

  .stream-stderr {
    background: var(--color-status-critical-bg);
  }

  .stream-notice {
    background: var(--color-status-paused-bg);
    color: var(--color-status-paused);
  }

  .lvl-error {
    border-left-color: var(--color-status-critical);
    color: var(--color-status-critical);
  }

  .lvl-warn {
    border-left-color: var(--color-status-warning);
    color: var(--color-status-warning);
  }

  .lvl-info {
    border-left-color: var(--color-status-healthy);
  }

  .lvl-debug {
    color: var(--color-text-muted);
  }

  .empty {
    margin: 0;
    padding: var(--space-3);
    color: var(--color-text-muted);
    font-family: inherit;
  }

  .jump {
    position: absolute;
    right: var(--space-4);
    bottom: var(--space-4);
    min-height: var(--target-size);
    padding: var(--space-1) var(--space-4);
    border: 1px solid var(--color-accent);
    border-radius: var(--radius-1);
    background: var(--color-accent);
    color: var(--color-accent-text);
    font-weight: 600;
    cursor: pointer;
  }
</style>
