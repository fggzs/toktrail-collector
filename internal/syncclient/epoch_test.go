package syncclient

import (
	"errors"
	"testing"
)

func epochPtr(v int64) *int64 { return &v }

func TestCheckSelfDataEpoch(t *testing.T) {
	cases := []struct {
		name       string
		selfEpoch  *int64
		stateEpoch int64
		wantStale  bool
	}{
		{"legacy server and legacy state", nil, 0, false},
		{"matching zero", epochPtr(0), 0, false},
		{"matching positive", epochPtr(3), 3, false},
		{"server advanced beyond local", epochPtr(4), 3, true},
		{"local advanced beyond server", epochPtr(3), 4, true},
		{"server stopped reporting after local advanced", nil, 3, true},
		{"server reports epoch for a local legacy device", epochPtr(1), 0, true},
		{"negative server epoch", epochPtr(-1), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSelfDataEpoch(SelfStatus{DataEpoch: tc.selfEpoch}, tc.stateEpoch)
			if tc.wantStale {
				if !errors.Is(err, ErrEpochStale) {
					t.Fatalf("want ErrEpochStale, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want pass, got %v", err)
			}
		})
	}
}

func TestCheckBatchDataEpoch(t *testing.T) {
	cases := []struct {
		name       string
		batchEpoch *int64
		stateEpoch int64
		wantStale  bool
	}{
		{"legacy batch on legacy state", nil, 0, false},
		{"epoch zero batch on legacy state", epochPtr(0), 0, false},
		{"matching positive", epochPtr(3), 3, false},
		{"unstamped batch after reset", nil, 3, true},
		{"old epoch batch after reset", epochPtr(2), 3, true},
		{"newer epoch batch on stale local state", epochPtr(4), 3, true},
		{"post-reset batch on legacy local state", epochPtr(1), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBatchDataEpoch(BatchRequest{BatchID: "b", DataEpoch: tc.batchEpoch}, tc.stateEpoch)
			if tc.wantStale {
				if !errors.Is(err, ErrEpochStale) {
					t.Fatalf("want ErrEpochStale, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want pass, got %v", err)
			}
		})
	}
}

func TestEpochValueNilIsZero(t *testing.T) {
	if epochValue(nil) != 0 {
		t.Fatal("nil epoch must normalize to 0")
	}
	if epochValue(epochPtr(5)) != 5 {
		t.Fatal("epoch pointer must unwrap")
	}
}
