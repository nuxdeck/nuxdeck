// SPDX-License-Identifier: AGPL-3.0-only

/** Where the installer script is served from (deploy/install/install.sh). */
export const INSTALL_URL = 'https://get.nuxdeck.com';

/**
 * The one command that installs the agent on a Linux host and enrols it (INS-4). The token is single-use
 * and expires in an hour; it is quoted so that no character in it can be read as shell syntax.
 */
export function linuxInstallCommand(token: string): string {
  const quoted = `'${token.replaceAll("'", `'\\''`)}'`;
  return `curl -fsSL ${INSTALL_URL} | sudo sh -s -- --agent --token ${quoted}`;
}
