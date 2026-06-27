package ironcore_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// Compile-time interface-satisfaction checks: both adapters must implement
// group.CredentialValidator with a value receiver.
var _ group.CredentialValidator = ironcore.PKIValidator{}
var _ group.CredentialValidator = ironcore.SPIFFEValidator{}

// makeTestCA creates a self-signed Ed25519 CA certificate and returns the CA
// private key, a CertPool containing it, and the raw DER bytes.
func makeTestCA(t *testing.T) (ed25519.PrivateKey, *x509.CertPool, []byte) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, caPub, caPriv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return caPriv, pool, caDER
}

// makeLeafCert creates a leaf certificate for leafPub signed by the given CA.
// If spiffeURI is non-empty a URI SAN is added; if empty, no URI SAN is set
// (used to exercise the "no SPIFFE SAN" error path).
func makeLeafCert(t *testing.T, leafPub ed25519.PublicKey, spiffeURI string, caDER []byte, caPriv ed25519.PrivateKey) []byte {
	t.Helper()
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert for leaf: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TestLeaf", Organization: []string{"example.org"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if spiffeURI != "" {
		u, err := url.Parse(spiffeURI)
		if err != nil {
			t.Fatalf("parse SPIFFE URI: %v", err)
		}
		tpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, leafPub, caPriv)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return der
}

// makeX509Cred builds an MLS x509 Credential from a DER-encoded leaf cert.
func makeX509Cred(leafDER []byte) tree.Credential {
	return tree.Credential{
		CredentialType: tree.CredentialTypeX509,
		Certificates:   []tree.Certificate{{CertData: leafDER}},
	}
}

// TestPKIValidator exercises PKIValidator: successful chain verify, unrelated
// root, key mismatch, and non-x509 credential.
func TestPKIValidator(t *testing.T) {
	caPriv, caPool, caDER := makeTestCA(t)
	leafSigner := makeSigner(t)
	leafPub := leafSigner.Public().(ed25519.PublicKey)
	sigPub := []byte(leafPub) // Ed25519 MLS SignaturePublicKey: raw 32 bytes
	leafDER := makeLeafCert(t, leafPub, "spiffe://example.org/workload/alice", caDER, caPriv)
	cred := makeX509Cred(leafDER)
	pki := ironcore.PKIValidator{Roots: caPool}

	// 1. Successful chain verify; returns the subject DN.
	identity, err := pki.Validate(cred, sigPub)
	if err != nil {
		t.Fatalf("PKIValidator.Validate: %v", err)
	}
	if len(identity) == 0 {
		t.Fatal("PKIValidator: expected non-empty identity")
	}

	// 2. Fails against an unrelated root pool.
	_, unrelatedPool, _ := makeTestCA(t)
	if _, err := (ironcore.PKIValidator{Roots: unrelatedPool}).Validate(cred, sigPub); err == nil {
		t.Fatal("PKIValidator: expected error for unrelated root pool, got nil")
	}

	// 3. Fails when sigPub ≠ cert key.
	otherSigner := makeSigner(t)
	otherPub := []byte(otherSigner.Public().(ed25519.PublicKey))
	if _, err := pki.Validate(cred, otherPub); err == nil {
		t.Fatal("PKIValidator: expected error for mismatched sigPub, got nil")
	}

	// 4. Fails for a non-x509 (basic) credential.
	if _, err := pki.Validate(makeCred("alice"), sigPub); err == nil {
		t.Fatal("PKIValidator: expected error for basic credential, got nil")
	}
}

// TestSPIFFEValidator exercises SPIFFEValidator: SPIFFE ID extraction, wrong
// trust domain, missing SPIFFE SAN, and optional chain verification.
func TestSPIFFEValidator(t *testing.T) {
	caPriv, caPool, caDER := makeTestCA(t)
	leafSigner := makeSigner(t)
	leafPub := leafSigner.Public().(ed25519.PublicKey)
	sigPub := []byte(leafPub)
	const spiffeURI = "spiffe://example.org/workload/alice"
	leafDER := makeLeafCert(t, leafPub, spiffeURI, caDER, caPriv)
	cred := makeX509Cred(leafDER)

	// 1. Returns the SPIFFE ID as identity.
	sv := ironcore.SPIFFEValidator{TrustDomain: "example.org"}
	identity, err := sv.Validate(cred, sigPub)
	if err != nil {
		t.Fatalf("SPIFFEValidator.Validate: %v", err)
	}
	if !bytes.Equal(identity, []byte(spiffeURI)) {
		t.Fatalf("SPIFFEValidator: identity = %q, want %q", identity, spiffeURI)
	}

	// 2. Fails for a wrong trust domain.
	if _, err := (ironcore.SPIFFEValidator{TrustDomain: "evil.example"}).Validate(cred, sigPub); err == nil {
		t.Fatal("SPIFFEValidator: expected error for wrong trust domain, got nil")
	}

	// 3. Fails when cert has no SPIFFE URI SAN.
	noSpiffeDER := makeLeafCert(t, leafPub, "", caDER, caPriv)
	if _, err := sv.Validate(makeX509Cred(noSpiffeDER), sigPub); err == nil {
		t.Fatal("SPIFFEValidator: expected error for cert with no SPIFFE SAN, got nil")
	}

	// 4. With Roots set, chain-verifies successfully.
	svWithRoots := ironcore.SPIFFEValidator{TrustDomain: "example.org", Roots: caPool}
	if _, err := svWithRoots.Validate(cred, sigPub); err != nil {
		t.Fatalf("SPIFFEValidator with Roots: %v", err)
	}

	// 5. With Roots set to a wrong pool, chain verification fails.
	_, wrongPool, _ := makeTestCA(t)
	svWrongRoots := ironcore.SPIFFEValidator{TrustDomain: "example.org", Roots: wrongPool}
	if _, err := svWrongRoots.Validate(cred, sigPub); err == nil {
		t.Fatal("SPIFFEValidator: expected error for wrong root pool, got nil")
	}
}
