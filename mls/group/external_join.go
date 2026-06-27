package group

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/keyschedule"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// PublishGroupInfo builds a signed GroupInfo for the current epoch, carrying the
// ratchet_tree (0x0002) and external_pub (0x0004) extensions, so a non-member can
// join via an external Commit (RFC 9420 §12.4.3.1/§12.4.3.2). The signer is this
// member (g.ownLeaf); confirmation_tag is recomputed from the current epoch.
func (g *Group) PublishGroupInfo() (*GroupInfo, error) {
	if g.signer == nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: no signer (pure receiver)")
	}
	rtree, err := g.tree.MarshalMLS()
	if err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: marshal tree: %w", err)
	}
	_, extPub, err := keyschedule.ExternalPub(g.suite, g.epoch.ExternalSecret)
	if err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: ExternalPub: %w", err)
	}
	confTag := keyschedule.ConfirmationTag(g.suite, g.epoch.ConfirmationKey, g.groupContext.ConfirmedTranscriptHash)
	gi := &GroupInfo{
		GroupContext: g.groupContext,
		Extensions: []tree.Extension{
			{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: rtree},
			{ExtensionType: ExtensionTypeExternalPub, ExtensionData: extPub},
		},
		ConfirmationTag: confTag,
		Signer:          g.ownLeaf,
	}
	if err := gi.Sign(g.suite, g.signer); err != nil {
		return nil, fmt.Errorf("group: PublishGroupInfo: Sign: %w", err)
	}
	return gi, nil
}
