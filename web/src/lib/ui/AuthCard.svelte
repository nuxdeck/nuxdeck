<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    intro?: string;
    children: Snippet;
  }

  let { title, intro, children }: Props = $props();
</script>

<main class="screen">
  <div class="card">
    <p class="brand">Nux Deck</p>
    <h1 id="page-title" tabindex="-1">{title}</h1>
    {#if intro}<p class="intro">{intro}</p>{/if}
    {@render children()}
  </div>
</main>

<style>
  .screen {
    min-height: 100vh;
    display: grid;
    place-items: start center;
    padding: var(--space-6) var(--space-4);
  }

  .card {
    width: 100%;
    max-width: 30rem;
    display: grid;
    gap: var(--space-4);
    padding: var(--space-6);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-2);
    background: var(--color-surface);
  }

  .brand {
    font-weight: 700;
    color: var(--color-text-muted);
  }

  h1 {
    font-size: var(--font-size-lg);
    line-height: 1.3;
  }

  h1:focus {
    outline: none;
  }

  .intro {
    color: var(--color-text-muted);
  }
</style>
