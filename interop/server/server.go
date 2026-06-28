package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/trevex/mls-go/interop/proto/mlspb"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/group"
	"github.com/trevex/mls-go/mls/tree"
)

type state struct {
	suite            cipher.Suite
	g                *group.Group
	pendingEpochAuth []byte // stashed by Commit; returned by HandlePendingCommit
}

type pendingKP struct {
	suite    cipher.Suite
	kpMsg    []byte
	initPriv []byte
	encPriv  []byte
	signer   crypto.Signer
}

// Server implements pb.MLSClientServer over the MLS engine. Embedding
// UnimplementedMLSClientServer makes every unsupported RPC return codes.Unimplemented.
type Server struct {
	pb.UnimplementedMLSClientServer
	mu     sync.Mutex
	states map[uint32]*state
	txns   map[uint32]*pendingKP
	nextID uint32
}

func New() *Server {
	return &Server{states: map[uint32]*state{}, txns: map[uint32]*pendingKP{}, nextID: 1}
}

func (s *Server) alloc() uint32 { id := s.nextID; s.nextID++; return id }

func lookupSuite(cs uint32) (cipher.Suite, error) {
	suite, ok := cipher.Lookup(cipher.CipherSuite(cs))
	if !ok {
		return cipher.Suite{}, status.Errorf(codes.InvalidArgument, "unsupported ciphersuite 0x%04x", cs)
	}
	return suite, nil
}

// newSigner generates a fresh signing key for the suite and returns the raw
// signature_priv the proto wants echoed back (Ed25519 seed / ECDSA scalar).
func newSigner(cs cipher.CipherSuite) (crypto.Signer, []byte, error) {
	switch cs {
	case cipher.X25519_AES128GCM_SHA256_Ed25519, cipher.XWING_AES256GCM_SHA256_Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv, priv.Seed(), nil
	case cipher.P256_AES128GCM_SHA256_P256:
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		// Bytes() returns the raw fixed-size big-endian P-256 scalar (32 bytes),
		// byte-identical to the deprecated sk.D.FillBytes(make([]byte, 32)).
		raw, err := sk.Bytes()
		if err != nil {
			return nil, nil, err
		}
		return sk, raw, nil
	default:
		return nil, nil, fmt.Errorf("no signer for suite 0x%04x", cs)
	}
}

func maxLifetime() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

func (s *Server) getState(id uint32) (*state, error) {
	st, ok := s.states[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown state_id %d", id)
	}
	return st, nil
}

func (st *state) resolveIdentity(identity []byte) (uint32, error) {
	for _, leaf := range st.g.ActiveLeaves() {
		cred, _, err := st.g.LeafCredential(leaf)
		if err != nil {
			continue
		}
		if bytes.Equal(cred.Identity, identity) {
			return leaf, nil
		}
	}
	return 0, status.Errorf(codes.NotFound, "no member with identity %q", identity)
}

func (s *Server) Name(_ context.Context, _ *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: "mls-go"}, nil
}

func (s *Server) SupportedCiphersuites(_ context.Context, _ *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: []uint32{
		uint32(cipher.X25519_AES128GCM_SHA256_Ed25519),
		uint32(cipher.P256_AES128GCM_SHA256_P256),
		// 0xF001 (X-Wing) intentionally omitted: private-use, self-interop only.
	}}, nil
}

func (s *Server) CreateGroup(_ context.Context, req *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	suite, err := lookupSuite(req.CipherSuite)
	if err != nil {
		return nil, err
	}
	signer, _, err := newSigner(cipher.CipherSuite(req.CipherSuite))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "newSigner: %v", err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: req.Identity}
	g, err := group.NewGroup(suite, req.GroupId, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NewGroup: %v", err)
	}
	g.SetEncryptHandshakes(req.EncryptHandshake)
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.alloc()
	s.states[id] = &state{suite: suite, g: g}
	return &pb.CreateGroupResponse{StateId: id}, nil
}

func (s *Server) StateAuth(_ context.Context, req *pb.StateAuthRequest) (*pb.StateAuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	return &pb.StateAuthResponse{StateAuthSecret: st.g.EpochAuthenticator()}, nil
}

func (s *Server) CreateKeyPackage(_ context.Context, req *pb.CreateKeyPackageRequest) (*pb.CreateKeyPackageResponse, error) {
	suite, err := lookupSuite(req.CipherSuite)
	if err != nil {
		return nil, err
	}
	signer, sigSeed, err := newSigner(cipher.CipherSuite(req.CipherSuite))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "newSigner: %v", err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: req.Identity}
	kp, initPriv, leafPriv, err := group.NewKeyPackage(suite, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "NewKeyPackage: %v", err)
	}
	kpMsg, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "EncodeKeyPackageMessage: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tid := s.alloc()
	s.txns[tid] = &pendingKP{suite: suite, kpMsg: kpMsg, initPriv: initPriv, encPriv: leafPriv, signer: signer}
	return &pb.CreateKeyPackageResponse{
		TransactionId:  tid,
		KeyPackage:     kpMsg,
		InitPriv:       initPriv,
		EncryptionPriv: leafPriv,
		SignaturePriv:  sigSeed,
	}, nil
}

func (s *Server) JoinGroup(_ context.Context, req *pb.JoinGroupRequest) (*pb.JoinGroupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.txns[req.TransactionId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown transaction_id %d", req.TransactionId)
	}
	g, err := group.JoinFromWelcome(tx.suite, req.Welcome, group.JoinOptions{
		KeyPackage:     tx.kpMsg,
		InitPriv:       tx.initPriv,
		EncryptionPriv: tx.encPriv,
		Signer:         tx.signer,
		RatchetTree:    req.RatchetTree, // optional external tree
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "JoinFromWelcome: %v", err)
	}
	g.SetEncryptHandshakes(req.EncryptHandshake)
	id := s.alloc()
	s.states[id] = &state{suite: tx.suite, g: g}
	// Consumed transaction: delete to release the stored private keys.
	delete(s.txns, req.TransactionId)
	return &pb.JoinGroupResponse{StateId: id, EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *Server) AddProposal(_ context.Context, req *pb.AddProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	kp, err := group.DecodeKeyPackageMessage(req.KeyPackage)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "DecodeKeyPackageMessage: %v", err)
	}
	msg, err := st.g.FrameProposal(group.ProposeAdd(kp))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FrameProposal: %v", err)
	}
	return &pb.ProposalResponse{Proposal: msg}, nil
}

func (s *Server) UpdateProposal(_ context.Context, req *pb.UpdateProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	prop, err := st.g.ProposeUpdate()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ProposeUpdate: %v", err)
	}
	msg, err := st.g.FrameProposal(prop)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FrameProposal: %v", err)
	}
	return &pb.ProposalResponse{Proposal: msg}, nil
}

func (s *Server) RemoveProposal(_ context.Context, req *pb.RemoveProposalRequest) (*pb.ProposalResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	leaf, err := st.resolveIdentity(req.RemovedId)
	if err != nil {
		return nil, err
	}
	msg, err := st.g.FrameProposal(group.ProposeRemove(leaf))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "FrameProposal: %v", err)
	}
	return &pb.ProposalResponse{Proposal: msg}, nil
}

func (s *Server) Commit(_ context.Context, req *pb.CommitRequest) (*pb.CommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	opt := group.CommitOptions{ByReference: req.ByReference}
	for _, pd := range req.ByValue {
		switch string(pd.ProposalType) {
		case "add":
			// Engine constraint: Welcome-producing Adds MUST be by-value.
			kp, err := group.DecodeKeyPackageMessage(pd.KeyPackage)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "by_value add: %v", err)
			}
			opt.ByValue = append(opt.ByValue, group.ProposeAdd(kp))
		case "remove":
			leaf, err := st.resolveIdentity(pd.RemovedId)
			if err != nil {
				return nil, err
			}
			opt.ByValue = append(opt.ByValue, group.ProposeRemove(leaf))
		default:
			return nil, status.Errorf(codes.Unimplemented, "by_value proposal_type %q not supported", pd.ProposalType)
		}
	}
	commit, welcome, err := st.g.Commit(opt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Commit: %v", err)
	}
	// Engine advances the committer in place; stash the new epoch auth for
	// HandlePendingCommit to report (proto's pending-commit semantics).
	st.pendingEpochAuth = st.g.EpochAuthenticator()
	return &pb.CommitResponse{Commit: commit, Welcome: welcome}, nil
}

func (s *Server) HandleCommit(_ context.Context, req *pb.HandleCommitRequest) (*pb.HandleCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	if err := st.g.ProcessCommit(req.Proposal, req.Commit); err != nil {
		return nil, status.Errorf(codes.Internal, "ProcessCommit: %v", err)
	}
	return &pb.HandleCommitResponse{StateId: req.StateId, EpochAuthenticator: st.g.EpochAuthenticator()}, nil
}

func (s *Server) HandlePendingCommit(_ context.Context, req *pb.HandlePendingCommitRequest) (*pb.HandleCommitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	if st.pendingEpochAuth == nil {
		return nil, status.Error(codes.FailedPrecondition, "no pending commit")
	}
	ea := st.pendingEpochAuth
	st.pendingEpochAuth = nil
	return &pb.HandleCommitResponse{StateId: req.StateId, EpochAuthenticator: ea}, nil
}

func (s *Server) Export(_ context.Context, req *pb.ExportRequest) (*pb.ExportResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	out, err := st.g.Exporter(req.Label, req.Context, int(req.KeyLength))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Exporter: %v", err)
	}
	return &pb.ExportResponse{ExportedSecret: out}, nil
}

func (s *Server) Protect(_ context.Context, req *pb.ProtectRequest) (*pb.ProtectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	ct, err := st.g.ProtectApplication(req.Plaintext, req.AuthenticatedData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ProtectApplication: %v", err)
	}
	return &pb.ProtectResponse{Ciphertext: ct}, nil
}

func (s *Server) Unprotect(_ context.Context, req *pb.UnprotectRequest) (*pb.UnprotectResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	pt, ad, err := st.g.UnprotectApplication(req.Ciphertext)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "UnprotectApplication: %v", err)
	}
	return &pb.UnprotectResponse{Plaintext: pt, AuthenticatedData: ad}, nil
}

func (s *Server) GroupInfo(_ context.Context, req *pb.GroupInfoRequest) (*pb.GroupInfoResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.getState(req.StateId)
	if err != nil {
		return nil, err
	}
	gi, err := st.g.PublishGroupInfo()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "PublishGroupInfo: %v", err)
	}
	giBytes, err := gi.MarshalMLS()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal group_info: %v", err)
	}
	// The ratchet_tree is carried inside the GroupInfo's 0x0002 extension; we mirror
	// it in the response's ratchet_tree field too (callers may pass external_tree).
	return &pb.GroupInfoResponse{GroupInfo: giBytes, RatchetTree: gi.RatchetTreeExtension()}, nil
}

func (s *Server) ExternalJoin(_ context.Context, req *pb.ExternalJoinRequest) (*pb.ExternalJoinResponse, error) {
	if len(req.Psks) > 0 {
		return nil, status.Error(codes.Unimplemented, "PSKs in external join not supported")
	}
	var gi group.GroupInfo
	if err := gi.UnmarshalMLS(req.GroupInfo); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "parse group_info: %v", err)
	}
	suite, err := lookupSuite(uint32(gi.GroupContext.CipherSuite))
	if err != nil {
		return nil, err
	}
	signer, _, err := newSigner(gi.GroupContext.CipherSuite)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "newSigner: %v", err)
	}
	cred := tree.Credential{CredentialType: tree.CredentialTypeBasic, Identity: req.Identity}
	g, commit, err := group.ExternalCommit(suite, gi, cred, signer, maxLifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ExternalCommit: %v", err)
	}
	// The external commit itself is always a PublicMessage (RFC 9420 §12.4.3.2);
	// EncryptHandshake only governs this member's future commits after joining.
	g.SetEncryptHandshakes(req.EncryptHandshake)
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.alloc()
	s.states[id] = &state{suite: suite, g: g}
	return &pb.ExternalJoinResponse{StateId: id, Commit: commit, EpochAuthenticator: g.EpochAuthenticator()}, nil
}

func (s *Server) Free(_ context.Context, req *pb.FreeRequest) (*pb.FreeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, req.StateId)
	return &pb.FreeResponse{}, nil
}
