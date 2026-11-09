package collection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"toktrail-collector/internal/local/grants"
	"toktrail-collector/internal/local/managedconsent"
)

// TestManagedCodeBuddyGrantSurvivesXDGEnvironmentChange pins the grant-sync
// boundary: a managed default grant stays the tool's default layout when the
// environment that produced its path disappears. The scheduled sync — which
// runs without the interactive shell's XDG_DATA_HOME — can neither add a
// second default layout at a newly discovered directory nor bypass the
// user's earlier decision to disable the old one. Path migration stays an
// explicit user operation.
func TestManagedCodeBuddyGrantSurvivesXDGEnvironmentChange(t *testing.T) {
	for _, tc := range []struct {
		name string
		// disabled marks a manual disable of the managed grant.
		disabled bool
		// system marks a disable the sync itself performed (device
		// change), which the new device's authorization restores.
		system bool
	}{
		{name: "old grant enabled stays the only default"},
		{name: "manually disabled grant is not bypassed", disabled: true},
		{name: "system-disabled grant restores at the old path", system: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			store := grants.New(t.TempDir())

			// The interactive shell set XDG_DATA_HOME; grant sync found
			// the data directory there and created the managed default.
			customBase := t.TempDir()
			customData := filepath.Join(customBase, "CodeBuddyExtension", "Data")
			if err := os.MkdirAll(customData, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XDG_DATA_HOME", customBase)
			if _, added, err := store.AddManagedGrant("codebuddy-history", customData); err != nil || !added {
				t.Fatalf("seed managed grant: added=%v err=%v", added, err)
			}
			switch {
			case tc.disabled:
				if _, _, err := store.Disable("codebuddy-history", customData); err != nil {
					t.Fatalf("manual disable: %v", err)
				}
			case tc.system:
				if _, err := store.DisableManaged(); err != nil {
					t.Fatalf("system disable: %v", err)
				}
			}

			// The scheduled task runs without the variable, and the
			// default XDG layout exists on disk: the old code path
			// would add a second default grant there.
			t.Setenv("XDG_DATA_HOME", "")
			defaultXDG := filepath.Join(home, ".local", "share", "CodeBuddyExtension", "Data")
			if err := os.MkdirAll(defaultXDG, 0o700); err != nil {
				t.Fatal(err)
			}

			view := managedconsent.View{ConsentRevision: 1, AllowedTools: []string{"CodeBuddy"}, DeviceGrantManaged: true}
			added, pending, err := mergeManagedGrants(store, view, home, nil)
			if err != nil {
				t.Fatalf("grant sync: %v", err)
			}

			cfg, err := store.Load()
			if err != nil {
				t.Fatalf("load grants: %v", err)
			}
			if len(cfg.Grants) != 1 {
				t.Fatalf("the sync must never add a second default grant, config now holds %d grants", len(cfg.Grants))
			}
			grant := cfg.Grants[0]
			if filepath.Clean(grant.Input) != filepath.Clean(customData) {
				t.Fatalf("the existing managed grant must stay the default layout, got %q", grant.Input)
			}
			if !grant.Managed {
				t.Fatal("the grant must stay managed")
			}
			switch {
			case tc.disabled:
				if grant.Enabled {
					t.Fatal("a manually disabled grant must not be re-enabled")
				}
				if len(added) != 0 {
					t.Fatalf("a manual disable must not be bypassed, added: %v", added)
				}
				if !strings.Contains(pending["CodeBuddy"], "manually disabled") {
					t.Fatalf("the manual disable must surface as pending, got %q", pending["CodeBuddy"])
				}
			case tc.system:
				if !grant.Enabled || grant.SystemDisabled {
					t.Fatal("a system-disabled grant must be restored at its original path")
				}
				if len(pending) != 0 {
					t.Fatalf("a restored grant must not be pending, got %v", pending)
				}
				found := false
				for _, entry := range added {
					if strings.Contains(entry, customData) && strings.Contains(entry, "restored") {
						found = true
					}
				}
				if !found {
					t.Fatalf("the restore must report the old path, added: %v", added)
				}
			default:
				if !grant.Enabled {
					t.Fatal("an enabled grant must stay enabled")
				}
				if len(added) != 0 {
					t.Fatalf("an already granted tool needs no changes, added: %v", added)
				}
				if len(pending) != 0 {
					t.Fatalf("an active default grant must not be pending, got %v", pending)
				}
			}

			enabled, err := store.Enabled()
			if err != nil {
				t.Fatalf("load enabled grants: %v", err)
			}
			wantEnabled := 1
			if tc.disabled {
				wantEnabled = 0
			}
			if len(enabled) != wantEnabled {
				t.Fatalf("expected %d enabled grants, got %d", wantEnabled, len(enabled))
			}
		})
	}
}

// TestManagedCodeBuddyGrantKeepsUserConfiguredPaths asserts the multi-path
// semantics stay the user's: a user-authored grant at another directory is
// never removed or touched when the sync decides about the managed default,
// no matter which environment the sync runs under.
func TestManagedCodeBuddyGrantKeepsUserConfiguredPaths(t *testing.T) {
	home := t.TempDir()
	store := grants.New(t.TempDir())

	customBase := t.TempDir()
	customData := filepath.Join(customBase, "CodeBuddyExtension", "Data")
	if err := os.MkdirAll(customData, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", customBase)
	if _, added, err := store.AddManagedGrant("codebuddy-history", customData); err != nil || !added {
		t.Fatalf("seed managed grant: added=%v err=%v", added, err)
	}

	// A user-authored grant at the Windows-style layout, explicitly enabled.
	userData := filepath.Join(home, "AppData", "Local", "CodeBuddyExtension", "Data")
	if err := os.MkdirAll(userData, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Enable("codebuddy-history", userData); err != nil {
		t.Fatalf("user grant: %v", err)
	}

	// The scheduled task loses the variable and the default XDG layout
	// appears on disk; neither grant may be dropped or duplicated.
	t.Setenv("XDG_DATA_HOME", "")
	defaultXDG := filepath.Join(home, ".local", "share", "CodeBuddyExtension", "Data")
	if err := os.MkdirAll(defaultXDG, 0o700); err != nil {
		t.Fatal(err)
	}

	view := managedconsent.View{ConsentRevision: 1, AllowedTools: []string{"CodeBuddy"}, DeviceGrantManaged: true}
	added, _, err := mergeManagedGrants(store, view, home, nil)
	if err != nil {
		t.Fatalf("grant sync: %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("no new default may be added: %v", added)
	}
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("load grants: %v", err)
	}
	if len(cfg.Grants) != 2 {
		t.Fatalf("both the managed default and the user grant must survive, got %d grants", len(cfg.Grants))
	}
	for _, grant := range cfg.Grants {
		switch filepath.Clean(grant.Input) {
		case filepath.Clean(customData):
			if !grant.Managed {
				t.Fatal("the managed grant must keep its managed flag")
			}
		case filepath.Clean(userData):
			if grant.Managed {
				t.Fatal("the user-authored grant must never become managed")
			}
			if !grant.Enabled {
				t.Fatal("the user-authored grant must stay enabled")
			}
		default:
			t.Fatalf("unexpected grant at %q", grant.Input)
		}
	}
}
