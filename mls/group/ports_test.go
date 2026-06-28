package group_test

import (
	"testing"

	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

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
