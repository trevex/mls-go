// Package interop_test is the gRPC conformance gate.
//
// Each sub-test spins up a fresh in-process gRPC server over a bufconn
// listener, drives the official MLSClient RPC scenarios, and asserts
// EpochAuthenticator (StateAuth) byte-equality across all live participants
// after every epoch change.
//
// Run: go test ./... (inside the interop/ module, or via `nix develop`)
package interop_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/trevex/mls-mlkem-go/interop/proto/mlspb"
	"github.com/trevex/mls-mlkem-go/interop/server"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// dial starts a fresh gRPC server backed by a bufconn listener and returns
// a ready client and a cleanup function.
func dial(t *testing.T) (pb.MLSClientClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterMLSClientServer(srv, server.New())
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return pb.NewMLSClientClient(conn), func() { _ = conn.Close(); srv.Stop() }
}

// assertStateAuth asserts that all supplied state IDs have the same epoch
// authenticator via the StateAuth RPC.
func assertStateAuth(t *testing.T, ctx context.Context, cli pb.MLSClientClient, label string, stateIDs ...uint32) {
	t.Helper()
	var ref []byte
	for i, id := range stateIDs {
		sa, err := cli.StateAuth(ctx, &pb.StateAuthRequest{StateId: id})
		if err != nil {
			t.Fatalf("%s: StateAuth(%d): %v", label, id, err)
		}
		if i == 0 {
			ref = sa.StateAuthSecret
			continue
		}
		if !bytes.Equal(ref, sa.StateAuthSecret) {
			t.Fatalf("%s: epoch_auth mismatch at index %d: got %x, want %x", label, i, sa.StateAuthSecret, ref)
		}
	}
}

// suiteNames maps ciphersuite uint32 to a human-readable label for t.Run.
func suiteName(cs uint32) string {
	switch cipher.CipherSuite(cs) {
	case cipher.X25519_AES128GCM_SHA256_Ed25519:
		return "0x0001"
	case cipher.P256_AES128GCM_SHA256_P256:
		return "0x0002"
	case cipher.XWING_AES256GCM_SHA256_Ed25519:
		return "0xF001"
	default:
		return fmt.Sprintf("0x%04x", cs)
	}
}

func testSuites() []uint32 {
	return []uint32{
		uint32(cipher.X25519_AES128GCM_SHA256_Ed25519),
		uint32(cipher.P256_AES128GCM_SHA256_P256),     // advertised; must gate-pass
		uint32(cipher.XWING_AES256GCM_SHA256_Ed25519), // self-interop only
	}
}

// ----------------------------------------------------------------------------
// Scenario 1: 1:1 welcome-join (the validated gate)
// ----------------------------------------------------------------------------

func TestOneToOneWelcomeJoin(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			cg, err := cli.CreateGroup(ctx, &pb.CreateGroupRequest{
				GroupId: []byte("g1"), CipherSuite: cs, Identity: []byte("alice"),
			})
			if err != nil {
				t.Fatal(err)
			}
			alice := cg.StateId

			kp, err := cli.CreateKeyPackage(ctx, &pb.CreateKeyPackageRequest{
				CipherSuite: cs, Identity: []byte("bob"),
			})
			if err != nil {
				t.Fatal(err)
			}

			// Welcome-producing Add must be by-value (engine constraint).
			com, err := cli.Commit(ctx, &pb.CommitRequest{
				StateId: alice,
				ByValue: []*pb.ProposalDescription{
					{ProposalType: []byte("add"), KeyPackage: kp.KeyPackage},
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			ha, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice})
			if err != nil {
				t.Fatal(err)
			}

			jg, err := cli.JoinGroup(ctx, &pb.JoinGroupRequest{
				TransactionId: kp.TransactionId, Welcome: com.Welcome,
			})
			if err != nil {
				t.Fatal(err)
			}

			// Response epoch authenticators must match.
			if !bytes.Equal(ha.EpochAuthenticator, jg.EpochAuthenticator) {
				t.Fatalf("epoch_auth mismatch in responses: alice %x  bob %x",
					ha.EpochAuthenticator, jg.EpochAuthenticator)
			}
			// Double-check via StateAuth RPC.
			assertStateAuth(t, ctx, cli, "1:1 join", alice, jg.StateId)
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario 2: 3-party join
// ----------------------------------------------------------------------------

func TestThreePartyJoin(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			cg, err := cli.CreateGroup(ctx, &pb.CreateGroupRequest{
				GroupId: []byte("g2"), CipherSuite: cs, Identity: []byte("alice"),
			})
			if err != nil {
				t.Fatal(err)
			}
			alice := cg.StateId

			// Alice adds Bob.
			kpBob, err := cli.CreateKeyPackage(ctx, &pb.CreateKeyPackageRequest{
				CipherSuite: cs, Identity: []byte("bob"),
			})
			if err != nil {
				t.Fatal(err)
			}
			com1, err := cli.Commit(ctx, &pb.CommitRequest{
				StateId: alice,
				ByValue: []*pb.ProposalDescription{
					{ProposalType: []byte("add"), KeyPackage: kpBob.KeyPackage},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice}); err != nil {
				t.Fatal(err)
			}
			jgBob, err := cli.JoinGroup(ctx, &pb.JoinGroupRequest{
				TransactionId: kpBob.TransactionId, Welcome: com1.Welcome,
			})
			if err != nil {
				t.Fatal(err)
			}
			bob := jgBob.StateId
			assertStateAuth(t, ctx, cli, "after bob joins", alice, bob)

			// Alice adds Carol.
			kpCarol, err := cli.CreateKeyPackage(ctx, &pb.CreateKeyPackageRequest{
				CipherSuite: cs, Identity: []byte("carol"),
			})
			if err != nil {
				t.Fatal(err)
			}
			com2, err := cli.Commit(ctx, &pb.CommitRequest{
				StateId: alice,
				ByValue: []*pb.ProposalDescription{
					{ProposalType: []byte("add"), KeyPackage: kpCarol.KeyPackage},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice}); err != nil {
				t.Fatal(err)
			}
			// Bob handles the commit (he is a non-committing member).
			if _, err := cli.HandleCommit(ctx, &pb.HandleCommitRequest{
				StateId: bob, Commit: com2.Commit,
			}); err != nil {
				t.Fatal(err)
			}
			// Carol joins.
			jgCarol, err := cli.JoinGroup(ctx, &pb.JoinGroupRequest{
				TransactionId: kpCarol.TransactionId, Welcome: com2.Welcome,
			})
			if err != nil {
				t.Fatal(err)
			}
			carol := jgCarol.StateId
			assertStateAuth(t, ctx, cli, "after carol joins", alice, bob, carol)
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario 3: Update commit
// Alice, Bob, Carol are in a group.  Bob proposes an Update, Alice commits it
// by reference.  All three must converge.
// ----------------------------------------------------------------------------

func TestUpdateCommit(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			alice, bob, carol := setup3Party(t, ctx, cli, cs, "g3u")

			// Bob proposes an Update.
			upd, err := cli.UpdateProposal(ctx, &pb.UpdateProposalRequest{StateId: bob})
			if err != nil {
				t.Fatal(err)
			}

			// Alice commits the Update by reference.
			com, err := cli.Commit(ctx, &pb.CommitRequest{
				StateId:     alice,
				ByReference: [][]byte{upd.Proposal},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice}); err != nil {
				t.Fatal(err)
			}
			// Bob and Carol handle the commit.
			for _, id := range []uint32{bob, carol} {
				if _, err := cli.HandleCommit(ctx, &pb.HandleCommitRequest{
					StateId: id, Proposal: [][]byte{upd.Proposal}, Commit: com.Commit,
				}); err != nil {
					t.Fatalf("HandleCommit(%d): %v", id, err)
				}
			}
			assertStateAuth(t, ctx, cli, "after update", alice, bob, carol)
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario 4: Remove commit
// Alice removes Carol.  Alice and Bob converge; Carol is evicted.
// ----------------------------------------------------------------------------

func TestRemoveCommit(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			alice, bob, _ := setup3Party(t, ctx, cli, cs, "g4r")

			// Alice removes Carol by identity.
			com, err := cli.Commit(ctx, &pb.CommitRequest{
				StateId: alice,
				ByValue: []*pb.ProposalDescription{
					{ProposalType: []byte("remove"), RemovedId: []byte("carol")},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice}); err != nil {
				t.Fatal(err)
			}
			if _, err := cli.HandleCommit(ctx, &pb.HandleCommitRequest{
				StateId: bob, Commit: com.Commit,
			}); err != nil {
				t.Fatal(err)
			}
			assertStateAuth(t, ctx, cli, "after remove", alice, bob)
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario 5: Protect / Unprotect
// Alice sends an application message that Bob decrypts.
// ----------------------------------------------------------------------------

func TestProtectUnprotect(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			alice, bob := setup2Party(t, ctx, cli, cs, "g5p")

			plaintext := []byte("hello mls")
			ad := []byte("aad")

			pr, err := cli.Protect(ctx, &pb.ProtectRequest{
				StateId: alice, Plaintext: plaintext, AuthenticatedData: ad,
			})
			if err != nil {
				t.Fatal(err)
			}
			unpr, err := cli.Unprotect(ctx, &pb.UnprotectRequest{
				StateId: bob, Ciphertext: pr.Ciphertext,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unpr.Plaintext, plaintext) {
				t.Fatalf("plaintext mismatch: got %q, want %q", unpr.Plaintext, plaintext)
			}
			if !bytes.Equal(unpr.AuthenticatedData, ad) {
				t.Fatalf("ad mismatch: got %q, want %q", unpr.AuthenticatedData, ad)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario 6: Export equality
// Alice and Bob independently export the same secret (same label/context/len).
// ----------------------------------------------------------------------------

func TestExportEquality(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			alice, bob := setup2Party(t, ctx, cli, cs, "g6e")

			ea, err := cli.Export(ctx, &pb.ExportRequest{
				StateId: alice, Label: "test", Context: []byte("ctx"), KeyLength: 32,
			})
			if err != nil {
				t.Fatal(err)
			}
			eb, err := cli.Export(ctx, &pb.ExportRequest{
				StateId: bob, Label: "test", Context: []byte("ctx"), KeyLength: 32,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ea.ExportedSecret, eb.ExportedSecret) {
				t.Fatalf("exported secrets differ:\n alice %x\n bob   %x", ea.ExportedSecret, eb.ExportedSecret)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Scenario 7: External join
// Alice and Bob are in a group.  Carol external-joins using GroupInfo.
// Alice and Bob process Carol's commit.  All three converge.
// ----------------------------------------------------------------------------

func TestExternalJoin(t *testing.T) {
	for _, cs := range testSuites() {
		cs := cs
		t.Run(suiteName(cs), func(t *testing.T) {
			t.Parallel()
			cli, done := dial(t)
			defer done()
			ctx := context.Background()

			alice, bob := setup2Party(t, ctx, cli, cs, "g7x")

			// Alice publishes GroupInfo.
			gi, err := cli.GroupInfo(ctx, &pb.GroupInfoRequest{StateId: alice})
			if err != nil {
				t.Fatal(err)
			}

			// Carol external-joins.
			ej, err := cli.ExternalJoin(ctx, &pb.ExternalJoinRequest{
				GroupInfo: gi.GroupInfo,
				Identity:  []byte("carol"),
			})
			if err != nil {
				t.Fatal(err)
			}
			carol := ej.StateId

			// Alice and Bob handle Carol's external commit.
			for _, id := range []uint32{alice, bob} {
				if _, err := cli.HandleCommit(ctx, &pb.HandleCommitRequest{
					StateId: id, Commit: ej.Commit,
				}); err != nil {
					t.Fatalf("HandleCommit(%d) after external-join: %v", id, err)
				}
			}
			assertStateAuth(t, ctx, cli, "after external-join", alice, bob, carol)
		})
	}
}

// ----------------------------------------------------------------------------
// Helpers: shared group setup
// ----------------------------------------------------------------------------

// setup2Party creates a 2-member group {alice, bob} on the given ciphersuite
// and returns (alice_state_id, bob_state_id).
func setup2Party(t *testing.T, ctx context.Context, cli pb.MLSClientClient, cs uint32, groupID string) (uint32, uint32) {
	t.Helper()
	cg, err := cli.CreateGroup(ctx, &pb.CreateGroupRequest{
		GroupId: []byte(groupID), CipherSuite: cs, Identity: []byte("alice"),
	})
	if err != nil {
		t.Fatal(err)
	}
	alice := cg.StateId

	kp, err := cli.CreateKeyPackage(ctx, &pb.CreateKeyPackageRequest{
		CipherSuite: cs, Identity: []byte("bob"),
	})
	if err != nil {
		t.Fatal(err)
	}
	com, err := cli.Commit(ctx, &pb.CommitRequest{
		StateId: alice,
		ByValue: []*pb.ProposalDescription{
			{ProposalType: []byte("add"), KeyPackage: kp.KeyPackage},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice}); err != nil {
		t.Fatal(err)
	}
	jg, err := cli.JoinGroup(ctx, &pb.JoinGroupRequest{
		TransactionId: kp.TransactionId, Welcome: com.Welcome,
	})
	if err != nil {
		t.Fatal(err)
	}
	return alice, jg.StateId
}

// setup3Party creates a 3-member group {alice, bob, carol} and returns
// (alice_state_id, bob_state_id, carol_state_id).
func setup3Party(t *testing.T, ctx context.Context, cli pb.MLSClientClient, cs uint32, groupID string) (uint32, uint32, uint32) {
	t.Helper()
	alice, bob := setup2Party(t, ctx, cli, cs, groupID)

	kp, err := cli.CreateKeyPackage(ctx, &pb.CreateKeyPackageRequest{
		CipherSuite: cs, Identity: []byte("carol"),
	})
	if err != nil {
		t.Fatal(err)
	}
	com, err := cli.Commit(ctx, &pb.CommitRequest{
		StateId: alice,
		ByValue: []*pb.ProposalDescription{
			{ProposalType: []byte("add"), KeyPackage: kp.KeyPackage},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.HandlePendingCommit(ctx, &pb.HandlePendingCommitRequest{StateId: alice}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.HandleCommit(ctx, &pb.HandleCommitRequest{
		StateId: bob, Commit: com.Commit,
	}); err != nil {
		t.Fatal(err)
	}
	jg, err := cli.JoinGroup(ctx, &pb.JoinGroupRequest{
		TransactionId: kp.TransactionId, Welcome: com.Welcome,
	})
	if err != nil {
		t.Fatal(err)
	}
	return alice, bob, jg.StateId
}
