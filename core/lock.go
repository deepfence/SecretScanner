package core

import (
	"fmt"
	"os"
	"sync"
	"syscall"
)

const lockFilePath = "/var/lock/deepfence-secret-scanner.lock"

type Flock struct {
	m sync.RWMutex
}

func NewFlock() *Flock {
	return &Flock{}
}

func getBootId() ([]byte, error) {
	bootId, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("failed to read boot id: %w", err)
	}
	return bootId, nil
}

// Acquires a shared lock on the file.
func (f *Flock) LockFile() error {
	f.m.Lock()
	defer f.m.Unlock()

	fd, err := os.OpenFile(lockFilePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open the lock file: %w", err)
	}
	defer fd.Close()

	bootId, err := getBootId()
	if err != nil {
		return err
	}

	file := os.NewFile(fd.Fd(), lockFilePath)
	file.Write(bootId)

	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_SH); err != nil {
		return fmt.Errorf("failed to acquire the lock file: %w", err)
	}

	return nil
}

// Releases the lock on the file.
func (f *Flock) UnlockFile() error {
	f.m.Lock()
	defer f.m.Unlock()

	fd, err := os.OpenFile(lockFilePath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open the lock file: %w", err)
	}
	defer fd.Close()

	if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("failed to unlock the lock file: %w", err)
	}

	return nil
}
