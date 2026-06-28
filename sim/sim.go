package sim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/trevex/mls-mlkem-go/ironcore"
	"github.com/trevex/mls-mlkem-go/mls/cipher"
	"github.com/trevex/mls-mlkem-go/mls/group"
	"github.com/trevex/mls-mlkem-go/mls/tree"
)

// fixedClock is an inert injectable clock (lifetimes are infinite; time never
// drives control flow — determinism rule).
type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(0, 0).UTC() }

func maxLifetime() tree.Lifetime { return tree.Lifetime{NotBefore: 0, NotAfter: ^uint64(0)} }

var errNoGI = errors.New("sim: no GroupInfo for ref")

func isLostRace(err error) bool    { return errors.Is(err, ironcore.ErrLostRace) }
func isSelfRemoved(err error) bool { return errors.Is(err, ironcore.ErrSelfRemoved) }

// kpEntry is one identity's published KeyPackage material per VNI.
type kpEntry struct {
	kpMsg, initPriv, leafPriv []byte
}

// kpDirectory maps identity → credential/signer and (identity,vni) → KeyPackage
// material (design spec N2 / §10.3).
type kpDirectory struct {
	creds   map[string]tree.Credential
	signers map[string]crypto.Signer
	kps     map[string]map[uint32]kpEntry // identity -> vni -> material
}

func newKPDirectory() *kpDirectory {
	return &kpDirectory{
		creds:   map[string]tree.Credential{},
		signers: map[string]crypto.Signer{},
		kps:     map[string]map[uint32]kpEntry{},
	}
}

func (d *kpDirectory) register(identity string, signer crypto.Signer) {
	d.creds[identity] = tree.Credential{
		CredentialType: tree.CredentialTypeBasic,
		Identity:       []byte(identity),
	}
	d.signers[identity] = signer
}

func (d *kpDirectory) cred(identity string) tree.Credential { return d.creds[identity] }

func (d *kpDirectory) newFounderGroup(suite cipher.Suite, vni uint32, identity string, signer crypto.Signer) *group.Group {
	g, err := group.NewGroup(suite, ironcore.GroupID(vni), d.cred(identity), signer, maxLifetime())
	if err != nil {
		panic(err)
	}
	return g
}

func (d *kpDirectory) publishKeyPackage(suite cipher.Suite, vni uint32, identity string, signer crypto.Signer) {
	kp, ip, lp, err := group.NewKeyPackage(suite, d.cred(identity), signer, maxLifetime())
	if err != nil {
		panic(err)
	}
	kpMsg, err := group.EncodeKeyPackageMessage(kp)
	if err != nil {
		panic(err)
	}
	if d.kps[identity] == nil {
		d.kps[identity] = map[uint32]kpEntry{}
	}
	d.kps[identity][vni] = kpEntry{kpMsg, ip, lp}
}

func (d *kpDirectory) resolver(vni uint32) ironcore.KeyPackageResolver {
	return func(identity []byte) ([]byte, bool) {
		if e, ok := d.kps[string(identity)][vni]; ok {
			return e.kpMsg, true
		}
		return nil, false
	}
}

func (d *kpDirectory) joinerMaterial(vni uint32, identity string) (kp, ip, lp []byte) {
	e := d.kps[identity][vni]
	return e.kpMsg, e.initPriv, e.leafPriv
}

// ─── determinism helpers (never range a map in control flow) ──────────────────

func sortedVNIKeys(m map[uint32]*vniState) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedEpochs(m map[uint64]ironcore.SA) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedActorEpochs(m map[ActorID]uint64) []ActorID {
	out := make([]ActorID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedRefKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupRefs(in [][]byte) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	for _, r := range in {
		if !seen[string(r)] {
			seen[string(r)] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}

func toGroupRefs(in [][]byte) []group.CommitRef {
	out := make([]group.CommitRef, len(in))
	for i, r := range in {
		out[i] = group.CommitRef(r)
	}
	return out
}

func vni32(v uint64) uint32 { return uint32(v) }

func sortedUint32[T any](m map[uint32]T) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedIntendedKeys(m map[uint32]map[string]bool) []uint32 { return sortedUint32(m) }

func sameSet(want, got map[string]bool) bool {
	if len(want) != len(got) {
		return false
	}
	for k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

func makeSigner() crypto.Signer {
	_, s, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return s
}

// ─── stub: Run is added in Task 11 (sim.go is extended there) ─────────────────
var _ = fmt.Sprintf // keep fmt imported for later use
