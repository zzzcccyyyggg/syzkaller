//go:build freebsd || netbsd || openbsd || linux || darwin

package manager

import (
	"os"
	"syscall"

	"github.com/google/syzkaller/pkg/osutil"
)

type sharedDBFileLock struct {
	file *os.File
}

func acquireSharedDBFileLock(path string, exclusive bool) (*sharedDBFileLock, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, osutil.DefaultFilePerm)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(file.Fd()), mode); err != nil {
		file.Close()
		return nil, err
	}
	return &sharedDBFileLock{file: file}, nil
}

func (lock *sharedDBFileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
