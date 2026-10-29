<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import HostEnrolment from '../lib/onboarding/HostEnrolment.svelte';
</script>

<h1 id="page-title" tabindex="-1">Add a host</h1>
<p class="question">Run one command on the machine you want to watch.</p>

<HostEnrolment />

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
