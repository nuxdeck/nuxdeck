<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import Button from '../ui/Button.svelte';
  import HostEnrolment from './HostEnrolment.svelte';

  interface Props {
    onFinish: () => void;
    onBack: () => void;
    busy: boolean;
  }

  let { onFinish, onBack, busy }: Props = $props();
</script>

<h2 id="wizard-step-title" tabindex="-1">Add your first host</h2>
<p class="intro">
  Install the agent on one Linux machine or run it as a container. You can add more hosts later from
  the inventory.
</p>

<HostEnrolment />

<div class="actions">
  <Button onclick={onFinish} disabled={busy}>{busy ? 'Finishing…' : 'Finish setup'}</Button>
  <Button variant="secondary" onclick={onBack} disabled={busy}>Back</Button>
</div>

<style>
  .intro {
    color: var(--color-text-muted);
    max-width: 62ch;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3);
    margin-top: var(--space-4);
  }
</style>
