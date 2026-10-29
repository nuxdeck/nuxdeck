// SPDX-License-Identifier: AGPL-3.0-only

import type { Host } from '../api/client';
import { auth } from '../auth.svelte';
import { SERVER_RUNNER } from './form';

/** Operators and admins may change checks; viewers only read. The server enforces it as well. */
export function canWriteChecks(): boolean {
  const roles = auth.user?.roles ?? [];
  return roles.includes('operator') || roles.includes('admin');
}

/** "nuxd" or the host name of the agent that runs the check. */
export function runnerLabel(runner: string, hosts: readonly Host[]): string {
  if (runner === SERVER_RUNNER) return 'Server';
  const host = hosts.find((h) => h.agent_id === runner);
  return host ? host.hostname : `Agent ${runner}`;
}
