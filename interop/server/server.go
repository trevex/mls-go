package server

import (
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

	pb "github.com/trevex/mls-mlkem-go/interop/proto/mlspb"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
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
		raw := make([]byte, 32)
		sk.D.FillBytes(raw)
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

func (s *Server) Name(_ context.Context, _ *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: "mls-mlkem-go"}, nil
}

func (s *Server) SupportedCiphersuites(_ context.Context, _ *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: []uint32{
		uint32(cipher.X25519_AES128GCM_SHA256_Ed25519),
		uint32(cipher.P256_AES128GCM_SHA256_P256),
		// 0xF001 (X-Wing) intentionally omitted: private-use, self-interop only.
	}}, nil
}

func (s *Server) CreateGroup(_ context.Context, req *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	if req.EncryptHandshake {
		return nil, status.Error(codes.Unimplemented, "encrypted (PrivateMessage) handshake not supported")
	}
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

func (s *Server) Free(_ context.Context, req *pb.FreeRequest) (*pb.FreeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, req.StateId)
	return &pb.FreeResponse{}, nil
}
