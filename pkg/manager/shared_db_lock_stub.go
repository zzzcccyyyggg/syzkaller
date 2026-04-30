//go:build !freebsd && !netbsd && !openbsd && !linux && !darwin

package manager

type sharedDBFileLock struct{}

func acquireSharedDBFileLock(string, bool) (*sharedDBFileLock, error) {
	return &sharedDBFileLock{}, nil
}

func (lock *sharedDBFileLock) Close() error {
	return nil
}
