<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import type { TotpEnrolment } from '../api/client';

  let { enrolment }: { enrolment: TotpEnrolment } = $props();
</script>

<!-- No QR code: it would need a client-side encoder (a new dependency). Every authenticator
     app also accepts the secret typed in, or the otpauth link opened on the same device. -->
<div class="setup">
  <p>
    In your authenticator app choose "Enter a setup key" and type this key (time-based, 6 digits):
  </p>
  <p class="secret"><code aria-label="Setup key">{enrolment.secret}</code></p>
  <p>
    On the device with the app installed you can also
    <a href={enrolment.otpauth_uri}>open the setup link</a>.
  </p>
</div>

<style>
  .setup {
    display: grid;
    gap: var(--space-2);
  }

  .secret code {
    display: block;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--color-border);
    border-radius: var(--radius-1);
    background: var(--color-surface-sunken);
    font-size: var(--font-size-md);
    letter-spacing: 0.08em;
    overflow-wrap: anywhere;
  }
</style>
