package group_test

import (
	"testing"

	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

func TestPorts_InMemoryStateStore(t *testing.T) {
	store := group.NewInMemoryStateStore()
	gid := group.GroupID([]byte("test-group"))

	// Load on an empty store returns ok=false.
	_, ok, err := store.Load(gid)
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if ok {
		t.Fatal("Load empty: expected ok=false")
	}

	// Save then Load returns the saved state.
	st := group.EpochState{Epoch: 3, GroupID: []byte("test-group"), Serialized: []byte("opaque")}
	if err := store.Save(gid, st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, ok, err := store.Load(gid)
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if !ok {
		t.Fatal("Load after save: expected ok=true")
	}
	if loaded.Epoch != 3 {
		t.Errorf("loaded.Epoch = %d, want 3", loaded.Epoch)
	}
	if string(loaded.Serialized) != "opaque" {
		t.Errorf("loaded.Serialized = %q, want %q", loaded.Serialized, "opaque")
	}

	// Wipe removes the state.
	if err := store.Wipe(gid); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	_, ok, err = store.Load(gid)
	if err != nil {
		t.Fatalf("Load after wipe: %v", err)
	}
	if ok {
		t.Fatal("Load after wipe: expected ok=false")
	}
}

func TestPorts_BasicCredentialValidator(t *testing.T) {
	v := group.BasicCredentialValidator{}

	// Non-empty basic credential accepted.
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: []byte("alice")}
	id, err := v.Validate(cred, []byte("sigpub"))
	if err != nil {
		t.Fatalf("Validate basic: %v", err)
	}
	if string(id) != "alice" {
		t.Errorf("returned identity = %q, want %q", id, "alice")
	}

	// Empty identity rejected.
	empty := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: nil}
	_, err = v.Validate(empty, []byte("sigpub"))
	if err == nil {
		t.Error("Validate empty identity: expected error")
	}

	// X509 credential rejected.
	x509cred := tree.Credential{CredentialType: tree.CredentialTypeX509}
	_, err = v.Validate(x509cred, []byte("sigpub"))
	if err == nil {
		t.Error("Validate x509: expected error")
	}
}
