package keyschedule

import "github.com/trevex/mls-mlkem-go/mls/cipher"

// EpochSecrets holds the secrets derived from one epoch of the key schedule
// (RFC 9420 §8). InitSecret is init_secret_[n], the input to the *next* epoch.
type EpochSecrets struct {
	JoinerSecret       []byte
	WelcomeSecret      []byte
	EpochSecret        []byte
	SenderDataSecret   []byte
	EncryptionSecret   []byte
	ExporterSecret     []byte
	ExternalSecret     []byte
	ConfirmationKey    []byte
	MembershipKey      []byte
	ResumptionPSK      []byte
	EpochAuthenticator []byte
	InitSecret         []byte
}

// JoinerSecret derives joiner_secret (RFC 9420 §8):
//
//	joiner_secret = ExpandWithLabel(
//	    KDF.Extract(init_secret_[n-1], commit_secret), "joiner", GroupContext, KDF.Nh)
//
// A nil commitSecret is treated as the all-zero KDF.Nh vector.
func JoinerSecret(suite cipher.Suite, initSecret, commitSecret, groupContext []byte) ([]byte, error) {
	if commitSecret == nil {
		commitSecret = make([]byte, suite.HashLen())
	}
	extracted, err := suite.Extract(initSecret, commitSecret) // Extract(salt=init_secret, IKM=commit_secret)
	if err != nil {
		return nil, err
	}
	return suite.ExpandWithLabel(extracted, "joiner", groupContext, suite.HashLen())
}

// DeriveEpochSecrets runs the full RFC 9420 §8 key schedule for one epoch. A nil
// pskSecret is treated as the all-zero KDF.Nh vector (psk_secret_[0]).
func DeriveEpochSecrets(suite cipher.Suite, initSecret, commitSecret, pskSecret, groupContext []byte) (EpochSecrets, error) {
	nh := suite.HashLen()
	if pskSecret == nil {
		pskSecret = make([]byte, nh)
	}
	joiner, err := JoinerSecret(suite, initSecret, commitSecret, groupContext)
	if err != nil {
		return EpochSecrets{}, err
	}
	member, err := suite.Extract(joiner, pskSecret) // Extract(salt=joiner_secret, IKM=psk_secret)
	if err != nil {
		return EpochSecrets{}, err
	}
	welcome, err := suite.DeriveSecret(member, "welcome")
	if err != nil {
		return EpochSecrets{}, err
	}
	epoch, err := suite.ExpandWithLabel(member, "epoch", groupContext, nh)
	if err != nil {
		return EpochSecrets{}, err
	}
	es := EpochSecrets{JoinerSecret: joiner, WelcomeSecret: welcome, EpochSecret: epoch}
	for _, d := range []struct {
		label string
		out   *[]byte
	}{
		{"sender data", &es.SenderDataSecret},
		{"encryption", &es.EncryptionSecret},
		{"exporter", &es.ExporterSecret},
		{"external", &es.ExternalSecret},
		{"confirm", &es.ConfirmationKey},
		{"membership", &es.MembershipKey},
		{"resumption", &es.ResumptionPSK},
		{"authentication", &es.EpochAuthenticator},
		{"init", &es.InitSecret},
	} {
		v, err := suite.DeriveSecret(epoch, d.label)
		if err != nil {
			return EpochSecrets{}, err
		}
		*d.out = v
	}
	return es, nil
}

// ExternalPub derives the group's external HPKE key pair from external_secret
// (RFC 9420 §8): external_priv, external_pub = KEM.DeriveKeyPair(external_secret).
func ExternalPub(suite cipher.Suite, externalSecret []byte) (priv, pub []byte, err error) {
	return suite.DeriveKeyPair(externalSecret)
}

// MLSExporter implements MLS-Exporter (RFC 9420 §8.5):
//
//	MLS-Exporter(Label, Context, Length) =
//	    ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)
func MLSExporter(suite cipher.Suite, exporterSecret []byte, label string, context []byte, length int) ([]byte, error) {
	derived, err := suite.DeriveSecret(exporterSecret, label)
	if err != nil {
		return nil, err
	}
	return suite.ExpandWithLabel(derived, "exported", suite.Hash(context), length)
}
