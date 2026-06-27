package group

import (
	"crypto"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// NewKeyPackage generates an init key, a leaf HPKE key, a signed key_package
// LeafNode and a signed KeyPackage (RFC 9420 §10). It returns the KeyPackage
// and the two private keys the holder keeps (initPriv for Welcome decryption,
// leafPriv for TreeKEM). Capabilities defaults are filled if zero.
func NewKeyPackage(suite cipher.Suite, cred tree.Credential, signer crypto.Signer, lifetime tree.Lifetime) (KeyPackage, []byte, []byte, error) {
	initPriv, initPub, err := suite.GenerateHPKEKeyPair()
	if err != nil {
		return KeyPackage{}, nil, nil, err
	}
	leafPriv, leafPub, err := suite.GenerateHPKEKeyPair()
	if err != nil {
		return KeyPackage{}, nil, nil, err
	}
	sigPub, err := suite.SignaturePublicKey(signer)
	if err != nil {
		return KeyPackage{}, nil, nil, err
	}
	ln := tree.LeafNode{
		EncryptionKey:  leafPub,
		SignatureKey:   sigPub,
		Credential:     cred,
		Capabilities:   defaultCapabilities(suite),
		LeafNodeSource: tree.LeafNodeSourceKeyPackage,
		Lifetime:       &lifetime,
	}
	if err := tree.SignLeafNode(suite, signer, &ln, nil, 0); err != nil {
		return KeyPackage{}, nil, nil, err
	}
	kp := KeyPackage{
		Version:     tree.ProtocolVersionMLS10,
		CipherSuite: suite.ID,
		InitKey:     initPub,
		LeafNode:    ln,
	}
	tbs, err := kp.tbsBytes()
	if err != nil {
		return KeyPackage{}, nil, nil, err
	}
	sig, err := suite.SignWithLabel(signer, "KeyPackageTBS", tbs)
	if err != nil {
		return KeyPackage{}, nil, nil, err
	}
	kp.Signature = sig
	return kp, initPriv, leafPriv, nil
}

// defaultCapabilities returns the minimum Capabilities for a new KeyPackage.
func defaultCapabilities(suite cipher.Suite) tree.Capabilities {
	return tree.Capabilities{
		Versions:     []tree.ProtocolVersion{tree.ProtocolVersionMLS10},
		CipherSuites: []cipher.CipherSuite{suite.ID},
		Credentials:  []tree.CredentialType{tree.CredentialTypeBasic},
	}
}
