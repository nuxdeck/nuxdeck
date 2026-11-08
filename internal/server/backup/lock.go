// SPDX-License-Identifier: AGPL-3.0-only

// Package backup takes and restores whole-state snapshots of the nuxd data directory
// (NFR-6). It uses the archive format in pkg/backup and runs only while no nuxd holds the
// data directory, so the copied files are a consistent point-in-time state.
package backup

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/nuxdeck/nuxdeck/internal/errcode"
)

// LockFile is the advisory lock nuxd holds on its data directory for its whole run.
const LockFile = "nuxd.lock"

// DataDirLock is an exclusive lock on a data directory. The kernel releases it when the
// process exits, so a crash never leaves the directory locked.
type DataDirLock struct {
	f *os.File
}

// LockDataDir takes the lock without waiting. A held lock is BAK-LOCK-001: the operator
// must stop nuxd first rather than have a backup race a live server.
func LockDataDir(dataDir string) (*DataDirLock, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, errcode.Wrap(errcode.SRVIO001, "create data directory", err)
	}
	f, err := os.OpenFile(filepath.Join(dataDir, LockFile), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // fixed name inside the data directory
	if err != nil {
		return nil, errcode.Wrap(errcode.SRVIO001, "open data directory lock", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // file descriptors fit in int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errcode.New(errcode.BAKLock001, "%s is in use; stop nuxd before backing up or restoring", dataDir)
		}
		return nil, errcode.Wrap(errcode.SRVIO001, "lock data directory", err)
	}
	return &DataDirLock{f: f}, nil
}

// Release drops the lock and closes the lock file. Calling it on nil is a no-op.
func (l *DataDirLock) Release() error {
	if l == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN) //nolint:gosec // file descriptors fit in int
	closeErr := l.f.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
