package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/statedir"
)

func TestForceRecollectFlagsFailBeforeStateOrNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"--force-recollect"},
		{"--all", "--force-recollect", "--replace-existing"},
		{"--all", "--expected-device", "unrelated"},
		{"--all", "--force-recollect", "--dry-run", "--yes"},
	} {
		var out bytes.Buffer
		if err := runResyncWithIO(args, strings.NewReader("y\n"), &out); err == nil {
			t.Fatalf("flags %v must fail", args)
		}
	}
}

func TestForceRecollectWrongDeviceDoesNotTouchState(t *testing.T) {
	dir := t.TempDir()
	store := statedir.New(dir)
	if err := store.Save(statedir.DeviceState{DeviceID: "device-a", DeviceSecret: strings.Repeat("a", 64), ServerURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = runResyncWithIO([]string{"--all", "--force-recollect", "--expected-device", "device-b", "--state-dir", dir}, strings.NewReader("y\n"), &out)
	if err == nil {
		t.Fatal("wrong-device guard must refuse")
	}
	after, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("wrong-device run rewrote device state")
	}
	if _, err := os.Stat(filepath.Join(dir, "force-recollect.json")); !os.IsNotExist(err) {
		t.Fatal("wrong-device run created a reset journal")
	}
	if strings.Contains(out.String(), "aaaaaaaa") || strings.Contains(out.String(), "127.0.0.1") {
		t.Fatal("force-recollect output leaked credential or server location")
	}
}
