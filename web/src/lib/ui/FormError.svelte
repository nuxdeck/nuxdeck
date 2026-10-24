<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { ApiError } from '../api/client';

  let { error }: { error: ApiError } = $props();
</script>

<!-- role="alert" announces the failure; the code matches the docs (docs/06-ux.md, Errors). -->
<div class="form-error" role="alert">
  <p class="what">{error.message}</p>
  <p>{error.hint}</p>
  <p class="code">Error code: {error.code}</p>
</div>

<style>
  .form-error {
    padding: var(--space-3);
    border: 1px solid var(--color-status-critical);
    border-radius: var(--radius-1);
    background: var(--color-status-critical-bg);
    color: var(--color-status-critical);
    display: grid;
    gap: var(--space-1);
  }

  .what {
    font-weight: 700;
  }

  .code {
    font-family: var(--font-mono);
    font-size: var(--font-size-sm);
  }
</style>
