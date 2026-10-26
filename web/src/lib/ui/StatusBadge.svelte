<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<script lang="ts">
  import Icon from './Icon.svelte';
  import type { IconName } from './icons';

  interface Props {
    /** A host status (online, offline, gone) or a container state (running, exited, ...). */
    status: string;
  }

  let { status }: Props = $props();

  type Tone = 'healthy' | 'warning' | 'critical' | 'unknown' | 'paused';
  // Status is never colour alone (WCAG 1.4.1): every state has its own icon and a word.
  const known: Record<string, { tone: Tone; icon: IconName; label: string }> = {
    online: { tone: 'healthy', icon: 'checkCircle', label: 'Online' },
    running: { tone: 'healthy', icon: 'checkCircle', label: 'Running' },
    offline: { tone: 'critical', icon: 'xCircle', label: 'Offline' },
    dead: { tone: 'critical', icon: 'alertTriangle', label: 'Dead' },
    restarting: { tone: 'warning', icon: 'refresh', label: 'Restarting' },
    paused: { tone: 'paused', icon: 'pauseCircle', label: 'Paused' },
    exited: { tone: 'unknown', icon: 'circle', label: 'Exited' },
    created: { tone: 'unknown', icon: 'circle', label: 'Created' },
    gone: { tone: 'unknown', icon: 'circle', label: 'Gone' },
  };

  const shown = $derived(
    known[status] ?? {
      tone: 'unknown' as Tone,
      icon: 'circle' as IconName,
      label: status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown',
    },
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

  .healthy {
    color: var(--color-status-healthy);
    background: var(--color-status-healthy-bg);
  }

  .warning {
    color: var(--color-status-warning);
    background: var(--color-status-warning-bg);
  }

  .critical {
    color: var(--color-status-critical);
    background: var(--color-status-critical-bg);
  }

  .unknown {
    color: var(--color-status-unknown);
    background: var(--color-status-unknown-bg);
  }

  .paused {
    color: var(--color-status-paused);
    background: var(--color-status-paused-bg);
  }
</style>
