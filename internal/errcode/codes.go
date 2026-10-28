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
		{CLIArg001, "Unknown or missing command", "The command is missing or not recognised.", "Run nux without arguments to list the commands."},
		{CLIArg002, "Invalid command-line argument", "A flag or argument is not valid.", "Check the usage text for the command."},
		{CLIArg003, "Command not implemented yet", "This command is a placeholder in this version.", "Update nux, or see the roadmap for when it arrives."},
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
