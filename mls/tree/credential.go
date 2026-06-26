package tree

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/syntax"
)

// CredentialType is the 2-byte MLS credential type (RFC 9420 §5.3).
type CredentialType uint16

const (
	CredentialTypeBasic CredentialType = 1
	CredentialTypeX509  CredentialType = 2
)

// Certificate wraps a single DER-encoded X.509 certificate (RFC 9420 §5.3).
type Certificate struct {
	CertData []byte // opaque cert_data<V>
}

// Credential authenticates a member's identity and signing key (RFC 9420 §5.3).
// Exactly one of Identity / Certificates is populated, per CredentialType.
type Credential struct {
	CredentialType CredentialType
	Identity       []byte        // basic: opaque identity<V>
	Certificates   []Certificate // x509: Certificate certificates<V>
}

func (c Credential) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(c.CredentialType))
	switch c.CredentialType {
	case CredentialTypeBasic:
		return b.WriteOpaqueV(c.Identity)
	case CredentialTypeX509:
		return syntax.WriteVectorV(b, c.Certificates, func(b *syntax.Builder, cert Certificate) error {
			return b.WriteOpaqueV(cert.CertData)
		})
	default:
		return fmt.Errorf("tree: unsupported credential type %d", c.CredentialType)
	}
}

func decodeCredential(c *syntax.Cursor) (Credential, error) {
	var cred Credential
	ct, err := c.ReadUint16()
	if err != nil {
		return cred, err
	}
	cred.CredentialType = CredentialType(ct)
	switch cred.CredentialType {
	case CredentialTypeBasic:
		if cred.Identity, err = c.ReadOpaqueV(); err != nil {
			return cred, err
		}
	case CredentialTypeX509:
		cred.Certificates, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (Certificate, error) {
			data, err := c.ReadOpaqueV()
			return Certificate{CertData: data}, err
		})
		if err != nil {
			return cred, err
		}
	default:
		return cred, fmt.Errorf("tree: unsupported credential type %d", cred.CredentialType)
	}
	return cred, nil
}

// MarshalMLS encodes the Credential to its MLS wire form.
func (c Credential) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := c.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a Credential, rejecting trailing bytes.
func (c *Credential) UnmarshalMLS(data []byte) error {
	cur := syntax.NewCursor(data)
	v, err := decodeCredential(cur)
	if err != nil {
		return err
	}
	if !cur.Empty() {
		return fmt.Errorf("tree: trailing bytes after Credential")
	}
	*c = v
	return nil
}
