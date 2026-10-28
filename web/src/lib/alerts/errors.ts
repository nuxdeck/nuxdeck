// SPDX-License-Identifier: AGPL-3.0-only

// Mirrors the ALR-* entries of internal/errcode/codes.go (a test keeps the two in step).
export const ALERT_HINTS: Record<string, { title: string; hint: string }> = {
  'ALR-RULE-001': {
    title: 'Alert already resolved',
    hint: 'Reload the list; a new alert opens if the condition returns.',
  },
  'ALR-SEND-001': {
    title: 'Notification rejected',
    hint: 'The service refused the message. Check the channel URL, token and chat, then send a test again.',
  },
  'ALR-SEND-002': {
    title: 'Notification not delivered',
    hint: 'The service did not answer. Check that it is reachable from the server; the next alert will try again.',
  },
  'ALR-SEND-003': {
    title: 'Destination blocked',
    hint: 'Use a public address, or have an admin turn on "Allow private addresses" for an internal target.',
  },
  'ALR-SEND-004': {
    title: 'Channel paused after failures',
    hint: 'Fix the channel, then wait a minute and send a test.',
  },
  'ALR-SEND-005': {
    title: 'Mail transport refused',
    hint: 'Use starttls or tls, and check the mail server certificate and credentials.',
  },
  'ALR-SEND-006': {
    title: 'Test sent too often',
    hint: 'Wait a few seconds and try again.',
  },
  'ALR-SEND-007': {
    title: 'Notification queue full',
    hint: 'Check slow or failing channels. Alerts are still recorded.',
  },
  'ALR-SEND-008': { title: 'Channel disabled', hint: 'Enable the channel, then try again.' },
};

export function describeAlertError(code: string): { title: string; hint: string } | undefined {
  return ALERT_HINTS[code];
}

/** The line shown after a failed test send: the code, what it means and what to do. */
export function testFailureText(code: string, message: string, hint: string): string {
  const known = ALERT_HINTS[code];
  return `${code} ${known?.title ?? message}. ${known?.hint ?? hint}`;
}
