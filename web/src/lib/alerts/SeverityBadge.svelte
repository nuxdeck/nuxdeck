<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import Icon from '../ui/Icon.svelte';
  import type { IconName } from '../ui/icons';

  let { severity }: { severity: string } = $props();

  // Severity is never colour alone (WCAG 1.4.1): each level has its own icon and its word.
  const looks: Record<string, { tone: string; icon: IconName; label: string }> = {
    critical: { tone: 'critical', icon: 'xCircle', label: 'Critical' },
    warning: { tone: 'warning', icon: 'alertTriangle', label: 'Warning' },
    info: { tone: 'info', icon: 'circle', label: 'Info' },
  };
  const shown = $derived(
    looks[severity] ?? { tone: 'info', icon: 'circle' as IconName, label: severity },
  );
</script>

<span class="badge {shown.tone}">
  <Icon name={shown.icon} size={16} />
  {shown.label}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: var(--space-1);
    padding: 0 var(--space-2);
    border-radius: var(--radius-1);
    font-size: var(--font-size-sm);
    font-weight: 600;
  }

  .critical {
    color: var(--color-status-critical);
    background: var(--color-status-critical-bg);
  }

  .warning {
    color: var(--color-status-warning);
    background: var(--color-status-warning-bg);
  }

  .info {
    color: var(--color-status-paused);
    background: var(--color-status-paused-bg);
  }
</style>
