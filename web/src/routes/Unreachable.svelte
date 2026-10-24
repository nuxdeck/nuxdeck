<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import { auth } from '../lib/auth.svelte';
  import AuthCard from '../lib/ui/AuthCard.svelte';
  import Button from '../lib/ui/Button.svelte';
  import FormError from '../lib/ui/FormError.svelte';
</script>

<AuthCard title="Cannot reach the server">
  {#if auth.failure}
    <FormError error={auth.failure} />
  {/if}
  <Button onclick={() => void auth.init()}>Try again</Button>
</AuthCard>
