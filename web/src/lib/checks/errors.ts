// SPDX-License-Identifier: AGPL-3.0-only

import type { Check } from '../api/client';

// Mirrors the CHK-* entries of internal/errcode/codes.go: the API sends only the code of a run.
const HINTS: Record<string, { title: string; hint: string }> = {
  'CHK-HTTP-001': {
    title: 'HTTP request failed',
    hint: 'Check the URL, that the service listens, and the timeout.',
  },
  'CHK-HTTP-002': {
    title: 'Unexpected HTTP status',
    hint: 'Check the service, or adjust the expected status codes.',
  },
  'CHK-HTTP-003': {
    title: 'Keyword not found',
    hint: 'Check the keyword, or that it appears early in the response.',
  },
  'CHK-HTTP-004': {
    title: 'JSON match failed',
    hint: 'Check the path and expected value against the real response.',
  },
  'CHK-HTTP-005': {
    title: 'Too many redirects',
    hint: 'Point the check at the final URL, or raise the redirect limit.',
  },
  'CHK-TCP-001': {
    title: 'TCP connection failed',
    hint: 'Check the host, the port and any firewall between the runner and the target.',
  },
  'CHK-DNS-001': {
    title: 'DNS lookup failed',
    hint: 'Check the name, the record type and the resolver.',
  },
  'CHK-DNS-002': {
    title: 'Unexpected DNS answer',
    hint: 'Check the record, or update the expected values.',
  },
  'CHK-TLS-001': {
    title: 'TLS handshake failed',
    hint: 'Check that the port speaks TLS and the server name matches.',
  },
  'CHK-TLS-002': {
    title: 'Certificate not trusted',
    hint: 'Fix the certificate, or turn chain verification off for this check.',
  },
  'CHK-TLS-003': { title: 'Certificate expires soon', hint: 'Renew the certificate.' },
  'CHK-PING-001': {
    title: 'No ping reply',
    hint: 'Check that the host is up and allows ICMP.',
  },
  'CHK-PING-002': {
    title: 'ICMP not permitted',
    hint: "Allow the runner's group in net.ipv4.ping_group_range, or run the check from another agent.",
  },
  'CHK-NET-001': {
    title: 'Target address blocked',
    hint: 'Use a public address, or run the check from an agent inside that network. Operators may allow private ranges per check.',
  },
  'CHK-RUN-001': {
    title: 'Runner offline',
    hint: 'Wait for the agent to reconnect.',
  },
  'CHK-RUN-002': { title: 'Runner busy', hint: 'The next scheduled run will try again.' },
  'CHK-RUN-003': {
    title: 'Runner did not answer',
    hint: "Check the agent's connection and load.",
  },
  'CHK-RUN-004': {
    title: 'Run requested too often',
    hint: 'Wait a few seconds and try again.',
  },
  'CHK-SEC-001': {
    title: 'Check credentials unavailable',
    hint: 'Save the check again with its credentials.',
  },
};

export function describeErrorCode(code: string): { title: string; hint: string } {
  return (
    HINTS[code] ?? { title: 'Check failed', hint: 'Open the details below, then try a manual run.' }
  );
}

/** What the check probes, as plain text. */
export function checkTarget(c: Check): string {
  switch (c.type) {
    case 'http':
      return `${c.http?.method ?? 'GET'} ${c.http?.url ?? ''}`.trim();
    case 'tcp':
      return `${c.tcp?.host ?? ''}:${c.tcp?.port ?? ''}`;
    case 'dns':
      return `${c.dns?.record_type ?? ''} ${c.dns?.name ?? ''}`.trim();
    case 'tls':
      return `${c.tls?.host ?? ''}:${c.tls?.port ?? 443}`;
    case 'ping':
      return c.ping?.host ?? '';
  }
}
