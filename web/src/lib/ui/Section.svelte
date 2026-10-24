<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { findSection } from '../router.svelte';
  import EmptyState from './EmptyState.svelte';

  interface Props {
    path: string;
    emptyTitle: string;
    hint: string;
  }

  let { path, emptyTitle, hint }: Props = $props();
  const section = $derived(findSection(path));
</script>

<h1 id="page-title" tabindex="-1">{section?.title}</h1>
<p class="question">{section?.question}</p>
<EmptyState title={emptyTitle}>{hint}</EmptyState>

<style>
  h1 {
    font-size: var(--font-size-xl);
    line-height: 1.2;
  }

  h1:focus {
    outline: none;
  }

  .question {
    margin: var(--space-1) 0 var(--space-6);
    color: var(--color-text-muted);
  }
</style>
