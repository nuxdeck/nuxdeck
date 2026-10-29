// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
	"github.com/nuxdeck/nuxdeck/internal/server/backup"
	"github.com/nuxdeck/nuxdeck/internal/server/config"
	"github.com/nuxdeck/nuxdeck/internal/server/store"
	"github.com/nuxdeck/nuxdeck/internal/server/store/secrets"
)

// runBackup implements `nuxd backup`. It needs nuxd stopped, because the data-directory lock
// is what makes the copy consistent.
func runBackup(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs2 := flag.NewFlagSet("nuxd backup", flag.ContinueOnError)
	fs2.SetOutput(stderr)
	configPath := fs2.String("config", getenvDefault(getenv, "NUXD_CONFIG", config.DefaultPath), "path to the YAML configuration file")
	out := fs2.String("out", "", "archive file to write (required; must be outside the data directory)")
	passFile := fs2.String("passphrase-file", "", "file holding the archive passphrase; the archive is encrypted")
	unencrypted := fs2.Bool("unencrypted", false, "write an unencrypted archive (required when --passphrase-file is not given)")
	includeKeys := fs2.Bool("include-master-key-unencrypted", false, "with --unencrypted, also copy the master key and the agent CA key")
	if err := fs2.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *out == "" {
		return failBackup(stderr, errcode.New(errcode.CLIArg002, "--out is required"), 2)
	}
	if (*passFile == "") == !*unencrypted {
		return failBackup(stderr, errcode.New(errcode.CLIArg002, "give exactly one of --passphrase-file or --unencrypted"), 2)
	}
	explicit := getenv("NUXD_CONFIG") != ""
	fs2.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "config" })
	cfg, err := config.Load(*configPath, explicit, getenv)
	if err != nil {
		return failBackup(stderr, err, 1)
	}

	var pass []byte
	if *passFile != "" {
		if pass, err = backup.ReadPassphraseFile(*passFile); err != nil {
			return failBackup(stderr, err, 1)
		}
	}
	key, err := secrets.ReadMasterKey(cfg.DataDir, cfg.Secrets.MasterKeyFile, getenv)
	if err != nil {
		return failBackup(stderr, err, 1)
	}
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return failBackup(stderr, errcode.Wrap(errcode.CLIArg002, "resolve --out", err), 2)
	}

	sum, err := backup.CreateFile(ctx, absOut, backup.CreateOptions{
		DataDir: cfg.DataDir, Passphrase: pass, IncludeKeys: *includeKeys, MasterKey: key, NuxdVersion: version,
	})
	if err != nil {
		return failBackup(stderr, err, 1)
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s: %d files, %d bytes, schema %d, encrypted=%t, master key included=%t\n",
		sum.Path, sum.Files, sum.Bytes, sum.SchemaVersion, sum.Encrypted, sum.MasterKeyIncluded)
	if sum.KeysExcluded {
		_, _ = fmt.Fprintln(stderr, "nuxd: warning: the master key and agent CA key were left out, so secrets cannot be decrypted and agents must re-enrol after a restore. Use --passphrase-file, or add --include-master-key-unencrypted to accept unencrypted keys.")
	}
	return 0
}

// runRestore implements `nuxd restore`. It refuses while a nuxd holds the data directory.
func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs2 := flag.NewFlagSet("nuxd restore", flag.ContinueOnError)
	fs2.SetOutput(stderr)
	in := fs2.String("in", "", "archive file to restore (required)")
	dataDir := fs2.String("data-dir", "", "absolute data directory to restore into (required)")
	passFile := fs2.String("passphrase-file", "", "file holding the archive passphrase, for encrypted archives")
	masterKeyFile := fs2.String("master-key-file", "", "master key file; opens a pre-upgrade archive, which is encrypted with the master key")
	if err := fs2.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *in == "" || *dataDir == "" {
		return failBackup(stderr, errcode.New(errcode.CLIArg002, "--in and --data-dir are required"), 2)
	}
	if *passFile != "" && *masterKeyFile != "" {
		return failBackup(stderr, errcode.New(errcode.CLIArg002, "give only one of --passphrase-file or --master-key-file"), 2)
	}
	var pass []byte
	var err error
	switch {
	case *passFile != "":
		if pass, err = backup.ReadPassphraseFile(*passFile); err != nil {
			return failBackup(stderr, err, 1)
		}
	case *masterKeyFile != "":
		if pass, err = secrets.ReadMasterKey("", *masterKeyFile, getenv); err != nil {
			return failBackup(stderr, err, 1)
		}
		if pass == nil {
			return failBackup(stderr, errcode.New(errcode.BAKPass001, "master key file %s is empty", *masterKeyFile), 1)
		}
	}
	maxSchema, err := store.LatestSchemaVersion()
	if err != nil {
		return failBackup(stderr, err, 1)
	}
	res, err := backup.Restore(ctx, backup.RestoreOptions{
		ArchivePath: *in, DataDir: *dataDir, Passphrase: pass, MaxSchemaVersion: maxSchema,
	})
	if err != nil {
		return failBackup(stderr, err, 1)
	}
	_, _ = fmt.Fprintf(stdout, "restored schema %d into %s; the previous data directory is %s\n", res.Manifest.SchemaVersion, *dataDir, res.PreviousDir)
	if !res.Manifest.MasterKeyIncluded {
		_, _ = fmt.Fprintln(stderr, "nuxd: warning: the archive has no master key. Set NUXD_MASTER_KEY or secrets.master_key_file to the original key, or stored secrets stay unreadable.")
	}
	return 0
}

func failBackup(stderr io.Writer, err error, code int) int {
	_, _ = fmt.Fprintln(stderr, "nuxd:", err)
	return code
}
