package ironcore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"net/url"

	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// Authorizer answers "is identity entitled to participate in vni?" The policy
// itself lives in the caller (metalnet control plane); the library only invokes it.
type Authorizer func(identity []byte, vni uint32) bool

// parseChain parses an MLS x509 credential into a leaf certificate and an
// intermediates pool ready for x509.Certificate.Verify.
func parseChain(cred tree.Credential) (leaf *x509.Certificate, intermediates *x509.CertPool, err error) {
	if cred.CredentialType != tree.CredentialTypeX509 || len(cred.Certificates) == 0 {
		return nil, nil, fmt.Errorf("ironcore: credential is not a non-empty x509 credential")
	}
	leaf, err = x509.ParseCertificate(cred.Certificates[0].CertData)
	if err != nil {
		return nil, nil, fmt.Errorf("ironcore: parse leaf cert: %w", err)
	}
	intermediates = x509.NewCertPool()
	for i, c := range cred.Certificates[1:] {
		ic, err := x509.ParseCertificate(c.CertData)
		if err != nil {
			return nil, nil, fmt.Errorf("ironcore: parse intermediate[%d]: %w", i, err)
		}
		intermediates.AddCert(ic)
	}
	return leaf, intermediates, nil
}

// bindSignatureKey checks the cert public key equals the MLS SignaturePublicKey
// encoding of sigPub (Ed25519: raw 32 bytes; ECDSA-P256: uncompressed SEC1 point
// — the exact encodings cipher.Suite.SignaturePublicKey produces).
func bindSignatureKey(leaf *x509.Certificate, sigPub []byte) error {
	switch pk := leaf.PublicKey.(type) {
	case ed25519.PublicKey:
		if !bytes.Equal([]byte(pk), sigPub) {
			return fmt.Errorf("ironcore: cert public key does not match MLS signature key")
		}
	case *ecdsa.PublicKey:
		// ECDH().Bytes() yields the uncompressed SEC1 point (0x04‖X‖Y),
		// byte-identical to the encoding cipher.Suite.SignaturePublicKey
		// produces. An ECDH() error means an incompatible key: treat as
		// mismatch.
		ecdhPub, err := pk.ECDH()
		if err != nil || !bytes.Equal(ecdhPub.Bytes(), sigPub) {
			return fmt.Errorf("ironcore: cert public key does not match MLS signature key")
		}
	default:
		return fmt.Errorf("ironcore: unsupported certificate public key type %T", pk)
	}
	return nil
}

// PKIValidator validates an MLS x509 credential by verifying the certificate
// chain against a trust bundle (design spec §8). The verified identity is the
// leaf certificate's subject DN string.
type PKIValidator struct {
	Roots *x509.CertPool // trust bundle
}

// Validate implements group.CredentialValidator. It chain-verifies the leaf
// certificate against v.Roots (required; returns an error if nil), then checks
// that the leaf public key matches the MLS SignaturePublicKey sigPub. Returns
// the subject DN on success.
func (v PKIValidator) Validate(cred tree.Credential, sigPub []byte) ([]byte, error) {
	if v.Roots == nil {
		return nil, fmt.Errorf("ironcore: PKIValidator requires a non-nil Roots trust bundle")
	}
	leaf, intermediates, err := parseChain(cred)
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("ironcore: PKI chain verification failed: %w", err)
	}
	if err := bindSignatureKey(leaf, sigPub); err != nil {
		return nil, err
	}
	return []byte(leaf.Subject.String()), nil
}

// SPIFFEValidator validates an MLS x509 credential as a SPIFFE SVID (design
// spec §8). It extracts the single spiffe:// URI SAN, checks the trust domain,
// chain-verifies against Roots, and returns the full SPIFFE ID as identity.
type SPIFFEValidator struct {
	TrustDomain string         // expected trust domain, e.g. "example.org"; "" accepts any
	Roots       *x509.CertPool // required trust bundle; Validate returns an error if nil
}

// Validate implements group.CredentialValidator. It chain-verifies the SVID
// against v.Roots (required; returns an error if nil), checks the cert key
// matches sigPub, extracts the spiffe:// URI SAN, and validates the trust
// domain. Returns the full SPIFFE ID on success.
func (v SPIFFEValidator) Validate(cred tree.Credential, sigPub []byte) ([]byte, error) {
	if v.Roots == nil {
		return nil, fmt.Errorf("ironcore: SPIFFEValidator requires a non-nil Roots trust bundle")
	}
	leaf, intermediates, err := parseChain(cred)
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("ironcore: SVID chain verification failed: %w", err)
	}
	if err := bindSignatureKey(leaf, sigPub); err != nil {
		return nil, err
	}
	id, err := spiffeID(leaf)
	if err != nil {
		return nil, err
	}
	if v.TrustDomain != "" && id.Host != v.TrustDomain {
		return nil, fmt.Errorf("ironcore: SPIFFE trust domain %q != expected %q", id.Host, v.TrustDomain)
	}
	return []byte(id.String()), nil
}

// spiffeID extracts the single spiffe:// URI SAN from leaf. It returns an
// error if there are zero or multiple SPIFFE URIs, or if the trust domain is
// empty.
func spiffeID(leaf *x509.Certificate) (*url.URL, error) {
	var found *url.URL
	for _, u := range leaf.URIs {
		if u.Scheme != "spiffe" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ironcore: multiple SPIFFE URI SANs in SVID")
		}
		found = u
	}
	if found == nil {
		return nil, fmt.Errorf("ironcore: no SPIFFE URI SAN in SVID")
	}
	if found.Host == "" {
		return nil, fmt.Errorf("ironcore: SPIFFE ID has empty trust domain")
	}
	return found, nil
}
