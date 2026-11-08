// SPDX-License-Identifier: Apache-2.0

// Package errcode declares every stable, user-visible error code. A code never
// changes meaning once released and a retired code is never reused.
package errcode

import (
	"errors"
	"fmt"
)

// Code has the form AREA-CATEGORY-NNN, for example SRV-CFG-001.
type Code string

// Declared codes, grouped by area: SRV (server), API, AUTH, CLI.
const (
	SRVCfg001    Code = "SRV-CFG-001"
	SRVCfg002    Code = "SRV-CFG-002"
	SRVIO001     Code = "SRV-IO-001"
	SRVIO002     Code = "SRV-IO-002"
	SRVIO003     Code = "SRV-IO-003"
	SRVMig001    Code = "SRV-MIG-001"
	SRVMig002    Code = "SRV-MIG-002"
	SRVMig003    Code = "SRV-MIG-003"
	SRVSec001    Code = "SRV-SEC-001"
	SRVSec002    Code = "SRV-SEC-002"
	APINF001     Code = "API-NF-001"
	APIVal001    Code = "API-VAL-001"
	APIInt001    Code = "API-INT-001"
	APILim001    Code = "API-LIM-001"
	APIPre001    Code = "API-PRE-001"
	APIPre002    Code = "API-PRE-002"
	AuthPwd001   Code = "AUTH-PWD-001" //nolint:gosec // an error code, not a credential
	AuthDeny001  Code = "AUTH-DENY-001"
	AuthDeny002  Code = "AUTH-DENY-002"
	AuthDeny003  Code = "AUTH-DENY-003"
	AuthDeny004  Code = "AUTH-DENY-004"
	AuthDeny005  Code = "AUTH-DENY-005"
	AuthSetup001 Code = "AUTH-SETUP-001"
	AuthSetup002 Code = "AUTH-SETUP-002"
	AuthRBAC001  Code = "AUTH-RBAC-001"
	AuthRBAC002  Code = "AUTH-RBAC-002"
	AuthRBAC003  Code = "AUTH-RBAC-003"
	AuthRBAC004  Code = "AUTH-RBAC-004"
	AuthTOTP001  Code = "AUTH-TOTP-001"
	AuthTOTP002  Code = "AUTH-TOTP-002"
	AuthTOTP003  Code = "AUTH-TOTP-003"
	AuthUser001  Code = "AUTH-USER-001"
	AuthUser002  Code = "AUTH-USER-002"
	AuthUser003  Code = "AUTH-USER-003"
	AuthToken001 Code = "AUTH-TOKEN-001" //nolint:gosec // an error code, not a credential
	AuthToken002 Code = "AUTH-TOKEN-002" //nolint:gosec // an error code, not a credential
	AuthToken003 Code = "AUTH-TOKEN-003" //nolint:gosec // an error code, not a credential
	AuthLock001  Code = "AUTH-LOCK-001"
	AuthOIDC001  Code = "AUTH-OIDC-001"
	AuthOIDC002  Code = "AUTH-OIDC-002"
	AuthOIDC003  Code = "AUTH-OIDC-003"
	AuthOIDC004  Code = "AUTH-OIDC-004"
	AuthOIDC005  Code = "AUTH-OIDC-005"
	AuthOIDC006  Code = "AUTH-OIDC-006"
	AuthOIDC007  Code = "AUTH-OIDC-007"
	AuthOIDC008  Code = "AUTH-OIDC-008"
	AuthOIDC009  Code = "AUTH-OIDC-009"
	AuthOIDC010  Code = "AUTH-OIDC-010"
	AuthOIDC011  Code = "AUTH-OIDC-011"
	LOGStr001    Code = "LOG-STR-001"
	LOGStr002    Code = "LOG-STR-002"
	LOGStr003    Code = "LOG-STR-003"
	LOGSrc001    Code = "LOG-SRC-001"
	LOGSrc002    Code = "LOG-SRC-002"
	LOGSrc003    Code = "LOG-SRC-003"
	GWTok001     Code = "GW-TOK-001" //nolint:gosec // an error code, not a credential
	GWCSR001     Code = "GW-CSR-001"
	GWCA001      Code = "GW-CA-001"
	GWAuth001    Code = "GW-AUTH-001"
	GWRate001    Code = "GW-RATE-001"
	GWStr001     Code = "GW-STR-001"
	GWStr002     Code = "GW-STR-002"
	GWStr003     Code = "GW-STR-003"
	GWStr004     Code = "GW-STR-004"
	SKGDeny001   Code = "SKG-DENY-001"
	SKGUps001    Code = "SKG-UPS-001"
	SKGUps002    Code = "SKG-UPS-002"
	SKGSock001   Code = "SKG-SOCK-001"
	AGTCol001    Code = "AGT-COL-001"
	AGTCol002    Code = "AGT-COL-002"
	AGTCol003    Code = "AGT-COL-003"
	AGTCol004    Code = "AGT-COL-004"
	AGTEnr001    Code = "AGT-ENR-001"
	AGTEnr002    Code = "AGT-ENR-002"
	AGTEnr003    Code = "AGT-ENR-003"
	AGTID001     Code = "AGT-ID-001"
	AGTID002     Code = "AGT-ID-002"
	AGTRev001    Code = "AGT-REV-001"
	CHKHTTP001   Code = "CHK-HTTP-001"
	CHKHTTP002   Code = "CHK-HTTP-002"
	CHKHTTP003   Code = "CHK-HTTP-003"
	CHKHTTP004   Code = "CHK-HTTP-004"
	CHKHTTP005   Code = "CHK-HTTP-005"
	CHKTCP001    Code = "CHK-TCP-001"
	CHKDNS001    Code = "CHK-DNS-001"
	CHKDNS002    Code = "CHK-DNS-002"
	CHKTLS001    Code = "CHK-TLS-001"
	CHKTLS002    Code = "CHK-TLS-002"
	CHKTLS003    Code = "CHK-TLS-003"
	CHKPing001   Code = "CHK-PING-001"
	CHKPing002   Code = "CHK-PING-002"
	CHKNet001    Code = "CHK-NET-001"
	CHKRun001    Code = "CHK-RUN-001"
	CHKRun002    Code = "CHK-RUN-002"
	CHKRun003    Code = "CHK-RUN-003"
	CHKRun004    Code = "CHK-RUN-004"
	ALRRule001   Code = "ALR-RULE-001"
	ALRSend001   Code = "ALR-SEND-001"
	ALRSend002   Code = "ALR-SEND-002"
	ALRSend003   Code = "ALR-SEND-003"
	ALRSend004   Code = "ALR-SEND-004"
	ALRSend005   Code = "ALR-SEND-005"
	ALRSend006   Code = "ALR-SEND-006"
	ALRSend007   Code = "ALR-SEND-007"
	ALRSend008   Code = "ALR-SEND-008"
	CHKSec001    Code = "CHK-SEC-001"
	STPSlug001   Code = "STP-SLUG-001"
	STPRate001   Code = "STP-RATE-001"
	CLIArg001    Code = "CLI-ARG-001"
	CLIArg002    Code = "CLI-ARG-002"
	CLIArg003    Code = "CLI-ARG-003"
	CLINuxd001   Code = "CLI-NUXD-001"
	CLIArg004    Code = "CLI-ARG-004"
	CLIAuth001   Code = "CLI-AUTH-001"
	CLICfg001    Code = "CLI-CFG-001"
	CLINet001    Code = "CLI-NET-001"
	CLINet002    Code = "CLI-NET-002"
	CLILog001    Code = "CLI-LOG-001"
	TELSend001   Code = "TEL-SEND-001"
	TELSend002   Code = "TEL-SEND-002"
	BAKFmt001    Code = "BAK-FMT-001"
	BAKVer001    Code = "BAK-VER-001"
	BAKAuth001   Code = "BAK-AUTH-001"
	BAKTrunc001  Code = "BAK-TRUNC-001"
	BAKPath001   Code = "BAK-PATH-001"
	BAKHash001   Code = "BAK-HASH-001"
	BAKLimit001  Code = "BAK-LIMIT-001"
	BAKPass001   Code = "BAK-PASS-001" //nolint:gosec // an error code name, not a credential
	BAKLock001   Code = "BAK-LOCK-001"
	BAKSrc001    Code = "BAK-SRC-001"
	BAKRest001   Code = "BAK-REST-001"
	BAKUpg001    Code = "BAK-UPG-001"
	BAKAudit001  Code = "BAK-AUDIT-001"
	AUDChain001  Code = "AUD-CHAIN-001"
	AUDExp001    Code = "AUD-EXP-001"
)

// Entry describes a code for users, docs and the UI.
type Entry struct {
	Code    Code
	Title   string
	Message string
	Hint    string
}

// Entries returns every declared code.
func Entries() []Entry {
	return []Entry{
		{SRVCfg001, "Configuration file unreadable", "The configuration file could not be read or parsed.", "Check the file path, permissions and YAML syntax, and remove unknown keys."},
		{SRVCfg002, "Invalid configuration value", "A configuration value is missing or not valid.", "Fix the named setting in the file or in its NUXD_* environment variable."},
		{SRVIO001, "Data directory unusable", "The data directory could not be created or opened.", "Check that the path exists or can be created and that nuxd's user can write to it."},
		{SRVIO002, "TLS certificate unavailable", "The TLS certificate could not be loaded or generated.", "Check the certificate and key files, or remove them to let nuxd generate a self-signed pair."},
		{SRVIO003, "Cannot listen on address", "nuxd could not bind a network address.", "Check that the port is free and that the address in the configuration is correct."},
		{SRVMig001, "Database migration failed", "A database migration could not be applied.", "Restore the database from a backup and report the error code."},
		{SRVMig002, "Database is newer than this nuxd", "The database was written by a newer nuxd version; downgrades are blocked.", "Run the newer nuxd version, or restore a backup taken before the upgrade."},
		{SRVMig003, "Applied migration was modified", "A migration recorded in the database no longer matches this build.", "Never edit an applied migration. Use the release the database was created with."},
		{SRVSec001, "Master key unusable", "The master encryption key is missing, malformed, or its file is readable by other users.", "Provide 32 random bytes, base64-encoded, in NUXD_MASTER_KEY or in the file named by secrets.master_key_file (mode 0600), or remove both so nuxd creates data_dir/master.key."},
		{SRVSec002, "Secret cannot be decrypted", "A stored secret failed authentication: it was altered, moved, or sealed under a different master key.", "Start nuxd with the master key the database was created with, or restore the database and key from the same backup."},
		{APINF001, "Resource not found", "No such endpoint or resource.", "Check the URL against the API documentation."},
		{APIVal001, "Invalid request", "The request body is missing, malformed or contains unknown fields.", "Send a JSON body with Content-Type: application/json and only the documented fields."},
		{APIInt001, "Internal error", "Something went wrong on the server.", "Try again; if it keeps happening, report the request ID from the X-Request-ID response header."},
		{APILim001, "Too many live connections", "The server is serving as many live update streams as it allows.", "Close other tabs or try again in a moment."},
		{APIPre001, "Item changed", "Someone else changed this item after you loaded it.", "Reload the item and apply your change again."},
		{APIPre002, "Version required", "This change needs the If-Match header with the ETag of the version you edited.", "Send the ETag from the last GET of the item in If-Match."},
		{AuthPwd001, "Password not accepted", "The password does not meet the password policy.", "Use at least 12 characters and avoid common or breached passwords."},
		{AuthDeny001, "Sign-in failed", "The email or password is incorrect.", "Check the email and password and try again."},
		{AuthDeny002, "Too many attempts", "Too many failed attempts from this address.", "Wait a few minutes and try again."},
		{AuthDeny003, "Sign-in required", "You must be signed in to do this.", "Sign in and try again."},
		{AuthDeny004, "Request blocked", "The request failed the cross-site request check.", "Reload the page and try again."},
		{AuthDeny005, "Permission denied", "Your role does not allow this action.", "Ask an administrator for the required role."},
		{AuthSetup001, "Setup token not accepted", "The setup token is missing or wrong.", "Run nuxd setup-token on the server and paste its output."},
		{AuthSetup002, "Setup already completed", "This server already has an administrator.", "Sign in instead."},
		{AuthRBAC001, "Action not permitted", "The action is not known to the permission policy, so it is denied.", "Report the request ID from the X-Request-ID response header."},
		{AuthRBAC002, "Outside your scope", "Your role is limited to certain environments or tags and does not cover this item.", "Ask an administrator to widen the scope of your role."},
		{AuthRBAC003, "Role binding not accepted", "The role binding has an unknown role or subject, or an invalid scope.", "Use the role admin, operator or viewer, a user ID or group name, and a scope of environments and tag sets."},
		{AuthRBAC004, "Role binding not found", "No such role binding.", "Reload the list of role bindings."},
		{AuthTOTP001, "Verification code not accepted", "The code is wrong, expired or was already used.", "Enter the current 6-digit code from your authenticator app, or a recovery code."},
		{AuthTOTP002, "Sign-in step expired", "The second sign-in step timed out or was used too often.", "Sign in again with your password."},
		{AuthTOTP003, "Two-factor state does not allow this", "Two-factor authentication is already on, or was not started.", "Start the enrolment again, or sign in with your authenticator."},
		{AuthUser001, "Email already in use", "An account with this email address already exists.", "Use a different email address."},
		{AuthUser002, "Last administrator", "This would leave the server without an enabled administrator.", "Make another user an administrator first."},
		{AuthUser003, "User not found", "No such user.", "Reload the list and try again."},
		{AuthToken001, "API token not accepted", "The API token is unknown, expired or revoked.", "Create a new token in your account settings."},
		{AuthToken002, "Token scope too wide", "A token can only grant roles and scopes its owner holds.", "Choose a role and scope no wider than your own."},
		{AuthToken003, "API token not found", "No such token for your account.", "Reload the list and try again."},
		{AuthLock001, "Account temporarily locked", "Too many failed attempts for this account from this address.", "Wait 15 minutes and try again."},
		{AuthOIDC001, "Single sign-on not set up", "No identity provider is configured for single sign-on.", "Ask an administrator to configure single sign-on in Settings, or sign in with your password."},
		{AuthOIDC002, "Sign-in attempt expired", "The sign-in attempt timed out or did not start in this browser.", "Start the sign-in again from the sign-in page."},
		{AuthOIDC003, "Identity provider did not complete sign-in", "The identity provider refused the sign-in or could not be reached.", "Try again. If it keeps failing, ask an administrator to check the single sign-on settings."},
		{AuthOIDC004, "Identity token not accepted", "The identity provider token failed a check on its signature, algorithm, issuer, audience, expiry or nonce.", "Ask an administrator to check the client ID, the issuer and the signing algorithm of the provider."},
		{AuthOIDC005, "Email not verified", "The identity provider did not confirm this email address, or sent none.", "Verify your email address with the identity provider, then sign in again."},
		{AuthOIDC006, "Email domain not allowed", "Single sign-on is limited to certain email domains, and yours is not one of them.", "Ask an administrator to allow your domain."},
		{AuthOIDC007, "No account for this sign-in", "No account matches this identity, and accounts are not created on sign-in.", "Ask an administrator to create your account or to allow automatic accounts."},
		{AuthOIDC008, "No role for this sign-in", "None of your identity provider groups has a role on this server.", "Ask an administrator to bind one of your groups to a role."},
		{AuthOIDC009, "Account disabled", "This account is disabled.", "Ask an administrator to enable it."},
		{AuthOIDC010, "Account already linked", "The email address or identity already belongs to another account.", "Ask an administrator to check the accounts."},
		{AuthOIDC011, "Public URL missing", "Single sign-on needs the public URL of this server for its redirect address.", "Set server.public_url (NUXD_PUBLIC_URL) to the https address users open, then restart nuxd."},
		{LOGStr001, "Too many live log streams", "The limit on concurrent live log streams was reached.", "Close other log tabs or try again in a moment."},
		{LOGStr002, "Invalid log stream request", "The log stream request was malformed or duplicated.", "Reload the page and open the log again."},
		{LOGStr003, "Log stream lagging", "Your connection could not keep up, so some log lines were dropped.", "Narrow the stream with a filter or watch a quieter source."},
		{LOGSrc001, "Log source unavailable", "The agent cannot read this container's logs through nux-sockguard.", "Check that the container exists, that nux-sockguard is running and that Docker or Podman is running."},
		{LOGSrc002, "Journal unavailable", "The agent cannot read the systemd journal for this unit.", "Check that journalctl is installed on the host and that the agent's user may read the journal (systemd-journal group)."},
		{LOGSrc003, "Host not connected", "The agent of this host is offline, so there is nothing to stream.", "Wait for the host to come back online."},
		{GWTok001, "Enrolment token not accepted", "The enrolment token is unknown, expired or already used.", "Create a new token in the UI; each token works once and expires after 1 hour."},
		{GWCSR001, "Certificate request rejected", "The certificate signing request is malformed or uses an unsupported key.", "Update the agent, which generates an ECDSA P-256 key and signs the request itself."},
		{GWCA001, "Agent CA unavailable", "The internal certificate authority could not be loaded or created.", "Check that the pki directory in the data directory is readable by nuxd and that ca.crt and ca.key belong together."},
		{GWAuth001, "Agent certificate not accepted", "The agent certificate is unknown, revoked or does not identify an agent.", "Enrol the host again with a new token."},
		{GWRate001, "Too many enrolment attempts", "Too many failed enrolment attempts from this address.", "Wait a few minutes and try again with a valid token."},
		{GWStr001, "Agent stream protocol error", "The first message on an agent stream must be Hello, sent promptly.", "Update the agent to a version that speaks protocol v1."},
		{GWStr002, "Agent message too large", "An agent message exceeded the 4 MB limit.", "Update the agent; metric batches are split to stay under 1 MB."},
		{GWStr003, "Replaced by a newer connection", "The same agent connected again, so the older stream was closed.", "Make sure only one agent runs per host."},
		{GWStr004, "Agent heartbeats missed", "No heartbeat arrived for three intervals, so the stream was closed.", "Check the network path between the agent and nuxd."},
		{SKGDeny001, "Request refused by nux-sockguard", "nux-sockguard forwards only a fixed list of read-only container API calls, and this was not one of them.", "Nothing to fix on the host; the agent never asks for anything outside the list."},
		{SKGUps001, "Container runtime unreachable", "nux-sockguard could not get an answer from the Docker or Podman socket.", "Check that Docker or Podman is running and that nux-sg can read its socket (docker group, or --upstream)."},
		{SKGUps002, "Container runtime response rejected", "The runtime's answer was too large or not in the expected shape, so it was not forwarded.", "Report the code and the runtime version; the response was dropped rather than passed on unfiltered."},
		{SKGSock001, "Socket cannot be set up", "nux-sockguard could not create its listening socket.", "Check that the directory exists and belongs to nux-sg, and that the path is not a regular file."},
		{AGTCol001, "Container inventory unavailable", "The agent cannot read containers through nux-sockguard.", "Check that nux-sockguard is running, that Docker or Podman is running, and that the agent's user is in the nux group."},
		{AGTCol002, "Host facts incomplete", "The agent could not read some host facts from /proc, /sys or /etc.", "Check that the agent's sandbox allows reading them; other facts are still reported."},
		{AGTCol003, "Host metrics unavailable", "The agent could not read host metrics from /proc or statfs.", "Check that the agent's sandbox allows reading /proc and the mounted file systems; other metrics are still reported."},
		{AGTCol004, "Container metrics unavailable", "The agent could not read container metrics from cgroups or through nux-sockguard.", "Check that cgroups v2 is mounted at /sys/fs/cgroup and that nux-sockguard is running; other metrics are still reported."},
		{AGTEnr001, "Agent already enrolled", "This host already holds an agent identity.", "Run nux agent run, or pass --force to enrol again with a new token."},
		{AGTEnr002, "Enrolment failed", "nuxd did not accept the enrolment request.", "Create a new token in the UI and run nux agent enroll again."},
		{AGTEnr003, "Gateway not trusted", "The server's certificate does not chain to the CA fingerprint in the token.", "Check that the token was copied completely and that nothing intercepts the connection to the gateway."},
		{AGTID001, "Agent identity unusable", "The agent's key, certificate or identity file is missing or damaged.", "Run nux agent enroll with a new token."},
		{AGTID002, "Agent certificate expired", "The agent was offline longer than its certificate lives and cannot renew it.", "Run nux agent enroll --force with a new token."},
		{AGTRev001, "Agent revoked", "nuxd no longer accepts this agent's certificate; it was revoked or removed.", "Run nux agent enroll --force with a new token to bring the host back."},
		{CHKHTTP001, "HTTP request failed", "The HTTP(S) request failed or timed out before a response arrived.", "Check the URL, that the service listens, and the timeout."},
		{CHKHTTP002, "Unexpected HTTP status", "The response status was not one of the expected codes.", "Check the service, or adjust the expected status codes."},
		{CHKHTTP003, "Keyword not found", "The response body did not contain the expected keyword within the size limit.", "Check the keyword, or that it appears early in the response."},
		{CHKHTTP004, "JSON match failed", "The JSON response did not satisfy the path condition, or was not valid JSON.", "Check the path and expected value against the real response."},
		{CHKHTTP005, "Too many redirects", "The request was redirected more often than the check allows.", "Point the check at the final URL, or raise the redirect limit."},
		{CHKTCP001, "TCP connection failed", "The TCP connection was refused, unreachable or timed out.", "Check the host, the port and any firewall between the runner and the target."},
		{CHKDNS001, "DNS lookup failed", "The name did not resolve, or the resolver did not answer.", "Check the name, the record type and the resolver."},
		{CHKDNS002, "Unexpected DNS answer", "The answer did not contain all the expected values.", "Check the record, or update the expected values."},
		{CHKTLS001, "TLS handshake failed", "The TLS handshake did not complete.", "Check that the port speaks TLS and the server name matches."},
		{CHKTLS002, "Certificate not trusted", "The certificate chain or name did not verify.", "Fix the certificate, or turn chain verification off for this check."},
		{CHKTLS003, "Certificate expires soon", "The certificate has expired or expires within the warning period.", "Renew the certificate."},
		{CHKPing001, "No ping reply", "The host did not answer any ICMP echo request in time.", "Check that the host is up and allows ICMP."},
		{CHKPing002, "ICMP not permitted", "This machine may not send unprivileged ICMP echo requests.", "Allow the runner's group in net.ipv4.ping_group_range, or run the check from another agent."},
		{CHKNet001, "Target address blocked", "The target resolves to an address that checks run by the server may not reach.", "Use a public address, or run the check from an agent inside that network. Operators may allow private ranges per check."},
		{CHKRun001, "Runner offline", "The agent that runs this check is not connected, so the check could not run.", "Wait for the agent to reconnect."},
		{CHKRun002, "Runner busy", "The agent could not take the check right now.", "The next scheduled run will try again."},
		{CHKRun003, "Runner did not answer", "The agent did not send a result in time.", "Check the agent's connection and load."},
		{CHKRun004, "Run requested too often", "This check was run on demand too recently.", "Wait a few seconds and try again."},
		{CHKSec001, "Check credentials unavailable", "A stored credential of this check could not be read.", "Save the check again with its credentials."},
		{STPSlug001, "Status page address taken", "Another status page already uses this slug.", "Choose a different slug."},
		{STPRate001, "Too many status page requests", "This address asked for status pages too often.", "Wait a minute and try again."},
		{ALRRule001, "Alert already resolved", "The alert is resolved, so it can no longer be acknowledged.", "Reload the alert list; a new alert opens if the condition returns."},
		{ALRSend001, "Notification rejected", "The receiving service refused the notification (a client error such as a bad webhook URL or token).", "Check the channel settings, then use the test button."},
		{ALRSend002, "Notification not delivered", "The receiving service did not answer, timed out or returned a server error, even after retries.", "Check that the service is reachable; Nux Deck retries on the next alert."},
		{ALRSend003, "Notification destination blocked", "The channel points at an address that notifications may not reach (loopback, link-local, cloud metadata or, unless allowed, a private range).", "Use a public address, or have an admin set allow_private on the channel for an internal target."},
		{ALRSend004, "Channel paused after failures", "Several deliveries to this channel failed in a row, so sending is paused for a short time.", "Fix the channel, then wait a minute or use the test button."},
		{ALRSend005, "Mail transport refused", "The mail server could not be reached securely: STARTTLS or TLS failed, or authentication was refused without encryption.", "Use security starttls or tls, and check the mail server's certificate and credentials."},
		{ALRSend006, "Test sent too often", "A test message was sent to this channel too recently.", "Wait a few seconds and try again."},
		{ALRSend007, "Notification queue full", "Too many notifications were waiting, so this one was dropped.", "Check slow or failing channels; alerts are still recorded."},
		{ALRSend008, "Channel disabled", "The channel is disabled, so nothing was sent.", "Enable the channel."},
		{AUDChain001, "Audit chain broken", "The hash chain of the audit log does not verify: an entry was modified, removed or inserted outside nuxd.", "Restore the database from a backup taken before the first broken entry and investigate who had write access to it."},
		{AUDExp001, "Audit export failed", "The audit export could not be completed.", "Try again; if it keeps happening, report the request ID from the X-Request-ID response header."},
		{CLIArg001, "Unknown or missing command", "The command is missing or not recognised.", "Run nux without arguments to list the commands."},
		{CLIArg002, "Invalid command-line argument", "A flag or argument is not valid.", "Check the usage text for the command."},
		{CLIArg003, "Command not implemented yet", "This command is a placeholder in this version.", "Update nux, or see the roadmap for when it arrives."},
		{CLINuxd001, "nuxd not found", "nux backup and nux restore run the nuxd binary, which holds the server data and master key, and it is not on PATH.", "Run them on the server host, or set NUX_NUXD_BIN to the nuxd binary's path."},
		{CLIArg004, "Ambiguous target", "More than one host, container or check matches the name you gave.", "Use the ID shown by the list command instead of the name."},
		{CLIAuth001, "Not signed in", "No API token is available for nux.", "Run nux login --server URL --token-file FILE, or set NUX_TOKEN."},
		{CLICfg001, "Config file unavailable", "The nux config file could not be read or written.", "Check that the file and its directory are readable and writable by your user."},
		{CLINet001, "Server unreachable", "nux could not complete the request to nuxd.", "Check the server URL and that nuxd is running, then try again."},
		{CLINet002, "Server certificate not trusted", "The server certificate is not signed by a trusted authority, or does not match the pinned fingerprint.", "Use --ca-file for a private CA, or --pin with the fingerprint shown by nuxd. Re-run login if the certificate was replaced on purpose."},
		{CLILog001, "Log stream stopped", "The log stream was refused or kept failing, so nux gave up.", "Check the target name, your access to it, and that the host is online."},
		{TELSend001, "Telemetry report not delivered", "The daily telemetry report could not reach the endpoint and was dropped.", "Nothing to fix; the next report is tried tomorrow. Turn telemetry off in Settings if this host should not reach the internet."},
		{TELSend002, "Telemetry endpoint refused the report", "The telemetry endpoint answered with an error status and the report was dropped.", "Nothing to fix; the next report is tried tomorrow."},
		{BAKFmt001, "Backup archive unreadable", "The file is not a Nux Deck backup or its contents are corrupt.", "Use an archive written by nuxd backup, and copy it again if the transfer may have failed."},
		{BAKVer001, "Backup from a newer version", "The archive was written by a newer nuxd than this one and cannot be restored safely.", "Install the nuxd version that wrote the archive, or a newer one, and restore with it."},
		{BAKAuth001, "Backup passphrase rejected", "The passphrase is wrong, or the archive was altered after it was written.", "Check the passphrase file. If it is correct, the archive is damaged: use another copy."},
		{BAKTrunc001, "Backup archive truncated", "The archive ends before its last section, so it is incomplete.", "Copy the archive again; nothing was restored."},
		{BAKPath001, "Unsafe backup entry", "The archive holds an entry with an absolute, parent or linked path, or a special file.", "Do not restore this archive; it was not written by nuxd backup."},
		{BAKHash001, "Backup checksum mismatch", "A file in the archive does not match its recorded checksum, or the file list does not match.", "Use another copy of the archive; nothing was restored."},
		{BAKLimit001, "Backup exceeds size limits", "The archive declares more data than the restore limits allow.", "Check the archive is not a decompression bomb; raise the limits only for a trusted archive."},
		{BAKPass001, "Backup passphrase missing", "The archive or command needs a passphrase, and none was given or the passphrase file is empty.", "Pass --passphrase-file with the passphrase used to create the archive, or pass --unencrypted when creating one without a passphrase."},
		{BAKLock001, "Data directory in use", "nuxd is running against this data directory, so it cannot be backed up or restored now.", "Stop nuxd (systemctl stop nuxd), run the command, then start nuxd again."},
		{BAKSrc001, "Data directory has unsupported entries", "The data directory holds a symbolic link or special file that a backup will not copy.", "Replace the link with the file it points to, or remove the special file, then back up again."},
		{BAKRest001, "Restore not completed", "The restore could not replace the data directory. The previous state was put back or left in place.", "Read the message, fix the cause (for example an existing .pre-restore directory), and run restore again."},
		{BAKAudit001, "Restored audit log is broken", "The archive's audit hash chain does not verify, so the restore was refused and the current data directory was left as it was.", "Use an archive taken before the broken entry, and investigate who could write to the database."},
		{BAKUpg001, "Pre-upgrade backup failed", "A backup could not be written before database migrations, so the migrations were not applied and nuxd did not start.", "Check free disk space and the backups directory permissions, then start nuxd again."},
	}
}

// Lookup returns the entry for a code.
func Lookup(c Code) (Entry, bool) {
	for _, e := range Entries() {
		if e.Code == c {
			return e, true
		}
	}
	return Entry{}, false
}

// Error carries a Code through the %w chain.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Err) }

func (e *Error) Unwrap() error { return e.Err }

// New returns an error with a code and a formatted detail message.
func New(c Code, format string, args ...any) error {
	return &Error{Code: c, Err: fmt.Errorf(format, args...)}
}

// Wrap attaches a code and context to err.
func Wrap(c Code, context string, err error) error {
	return &Error{Code: c, Err: fmt.Errorf("%s: %w", context, err)}
}

// CodeOf returns the outermost code in err's chain, or "" if there is none.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
