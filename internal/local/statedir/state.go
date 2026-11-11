package statedir

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const stateFileName = "device.json"

type DeviceState struct {
	ServerURL         string `json:"serverUrl,omitempty"`
	ApplicationID     string `json:"applicationId,omitempty"`
	ExternalSubjectID string `json:"externalSubjectId,omitempty"`
	DeviceID          string `json:"deviceId,omitempty"`
	DeviceName        string `json:"deviceName,omitempty"`
	Platform          string `json:"platform,omitempty"`
	DeviceSecret      string `json:"deviceSecret,omitempty"`
	BindRequestID     string `json:"bindRequestId,omitempty"`
	ConsentRevision   int64  `json:"consentRevision,omitempty"`
	// DataEpoch is the device's durable data epoch: the fence against
	// pre-reset data flowing back into a device the server has usage-reset.
	// It is written ONLY by an initial bind (a state that had no device
	// bound yet adopts the receipt's epoch, 0 for both old servers and
	// fresh devices) and by an explicit force-recollect journal
	// transition performed by the recollect driver. It is NEVER advanced
	// from a device self snapshot or a re-bind: a server that moved on
	// leaves the local epoch stale on purpose, so the sync epoch fences
	// block every ordinary upload until the reset flow completes. 0 means
	// legacy/initial (the epoch fence then tolerates batches without a
	// dataEpoch stamp).
	DataEpoch                 int64      `json:"dataEpoch,omitempty"`
	BoundAt                   time.Time  `json:"boundAt,omitempty"`
	UploadAuthorized          bool       `json:"uploadAuthorized"`
	PublicAuthorized          bool       `json:"publicAuthorized"`
	Revoked                   bool       `json:"revoked"`
	LastCheckedAt             time.Time  `json:"lastCheckedAt,omitempty"`
	LastSyncedAt              time.Time  `json:"lastSyncedAt,omitempty"`
	LastSyncBatchID           string     `json:"lastSyncBatchId,omitempty"`
	LastSyncStatus            string     `json:"lastSyncStatus,omitempty"`
	LastSyncAcceptedRecords   int        `json:"lastSyncAcceptedRecords"`
	LastSyncRejectedRecords   int        `json:"lastSyncRejectedRecords"`
	PendingBindFingerprint    string     `json:"pendingBindFingerprint,omitempty"`
	LastBindFingerprint       string     `json:"lastBindFingerprint,omitempty"`
	ConnectReceiptHash        string     `json:"connectReceiptHash,omitempty"`
	PendingConnectReceiptHash string     `json:"pendingConnectReceiptHash,omitempty"`
	HistoryFrom               *time.Time `json:"historyFrom,omitempty"`
	HistoryDays               int        `json:"historyDays,omitempty"`
	UpdatedAt                 time.Time  `json:"updatedAt,omitempty"`
}

type Store struct{ dir string }

func New(dir string) Store { return Store{dir: strings.TrimSpace(dir)} }

// Dir returns the state directory the store reads and writes. An empty
// string means the store was built without a directory (DefaultDir must
// be used instead); callers use it to locate sibling state-dir files
// such as the force-recollect journal.
func (s Store) Dir() string { return s.dir }

func DefaultDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("TOKTRAIL_HOME")); v != "" {
		return v, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "toktrail"), nil
}

func (s Store) Path() string { return filepath.Join(s.dir, stateFileName) }

func (s Store) Load() (DeviceState, error) {
	b, err := os.ReadFile(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return DeviceState{}, nil
	}
	if err != nil {
		return DeviceState{}, err
	}
	var st DeviceState
	if err := json.Unmarshal(b, &st); err != nil {
		return DeviceState{}, err
	}
	return st, nil
}

func (s Store) Save(st DeviceState) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	st.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path())
}
