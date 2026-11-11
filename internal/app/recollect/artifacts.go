package recollect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// freezeStores binds the confirmed rebuild to the exact baselines and
// quarantined records that will be installed. Batch-only hashes cannot
// protect a quarantine recovery upload or an altered increment baseline.
func freezeStores(stateDir, tempDir string) (map[string]string, error) {
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return nil, err
	}
	manifest := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if !ordinaryStore(name) || name == "batches" || name == "resync" {
			continue
		}
		path := filepath.Join(tempDir, name)
		if err := secureWithin(stateDir, path); err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("pre-scan state artifact must be a regular file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		manifest[name] = hex.EncodeToString(sum[:])
	}
	return manifest, nil
}

func verifyStoreFile(stateDir, path, want string) error {
	if err := secureWithin(stateDir, path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("frozen state artifact must be a regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("frozen state artifact %s changed since the confirmed pre-scan; refusing to install or recover its contents", filepath.Base(path))
	}
	return nil
}

func verifyFrozenStores(stateDir string, j job) error {
	// Once installation converged, uploads legitimately advance message
	// progress, outbox receipts, and quarantine. Only pre-install state is
	// immutable; a resume of upload must not compare it to old baselines.
	if j.Phase == phaseUpload || j.Install != nil && j.Install.Stores {
		return nil
	}
	for name, hash := range j.StoreHashes {
		path := filepath.Join(j.TempStateDir, name)
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && j.Phase == phaseReset && name != "outbox.json" {
			path = filepath.Join(stateDir, name)
		} else if err != nil {
			return err
		}
		if err := verifyStoreFile(stateDir, path, hash); err != nil {
			return err
		}
	}
	return nil
}
