<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import Icon from '../ui/Icon.svelte';

  interface Props {
    hostsConnected: boolean;
  }

  let { hostsConnected }: Props = $props();
</script>

<h2 id="wizard-step-title" tabindex="-1">Setup is complete</h2>
<p class="intro">
  {hostsConnected
    ? 'Your first host is connected and reporting.'
    : 'You can add hosts at any time from the inventory.'}
  The Overview lists the next steps: an uptime check, a notification channel, a teammate and a status
  page.
</p>
<p class="next">
  <a class="button-link" href="/">Go to the Overview</a>
  <a href="/inventory/add"><Icon name="server" size={16} /> Add another host</a>
</p>

<style>
  .intro {
    color: var(--color-text-muted);
    max-width: 62ch;
  }

  .next {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-4);
  }
</style>
