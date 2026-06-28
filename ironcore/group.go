package ironcore

import "github.com/trevex/mls-go/mls/group"

// VNIGroup is a thin handle pairing a VNI with its *group.Group (design spec §10.1).
// It is the home for DeriveSA and the VNI-scoped GroupID. Membership-controller
// logic (designated-committer election, external-commit join) is deferred.
type VNIGroup struct {
	vni uint32
	g   *group.Group
}

// NewVNIGroup binds vni to the given MLS group.
func NewVNIGroup(vni uint32, g *group.Group) *VNIGroup { return &VNIGroup{vni: vni, g: g} }

// VNI returns the VNI this group protects.
func (v *VNIGroup) VNI() uint32 { return v.vni }

// GroupID returns the stable MLS GroupID for the VNI (design spec §10.1).
func (v *VNIGroup) GroupID() []byte { return GroupID(v.vni) }

// Group returns the underlying *group.Group.
func (v *VNIGroup) Group() *group.Group { return v.g }

// Epoch returns the current MLS epoch.
func (v *VNIGroup) Epoch() uint64 { return v.g.Epoch() }

// DeriveSA derives the current IronCore ESP SA for this VNI group (design spec §10.4).
func (v *VNIGroup) DeriveSA() (SA, error) { return DeriveSAKeys(v.g, v.vni) }
