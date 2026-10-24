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

// Declared codes, grouped by area: SRV (server), API, CLI.
const (
	SRVCfg001 Code = "SRV-CFG-001"
	SRVCfg002 Code = "SRV-CFG-002"
	SRVIO001  Code = "SRV-IO-001"
	SRVIO002  Code = "SRV-IO-002"
	SRVIO003  Code = "SRV-IO-003"
	SRVMig001 Code = "SRV-MIG-001"
	SRVMig002 Code = "SRV-MIG-002"
	SRVMig003 Code = "SRV-MIG-003"
	APINF001  Code = "API-NF-001"
	CLIArg001 Code = "CLI-ARG-001"
	CLIArg002 Code = "CLI-ARG-002"
	CLIArg003 Code = "CLI-ARG-003"
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
		{APINF001, "Resource not found", "No such endpoint or resource.", "Check the URL against the API documentation."},
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
